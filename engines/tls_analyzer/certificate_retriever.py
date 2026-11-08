import socket
import ssl

from cryptography import x509

from .analysis_result import TLSAnalysisResult
from .ssrf_guard import UnsafeAddressError, resolve_public_ip

# OpenSSL X509_V_ERR_* codes -> plain reasons
_VERIFY_CODE_REASONS = {
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",
    19: "unknown_issuer",
    20: "unknown_issuer",
    21: "unknown_issuer",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}


class CertificateRetriever:
    def __init__(self, host: str, port: int, result: TLSAnalysisResult, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.result = result
        self.timeout = timeout

    def retrieve(self) -> x509.Certificate | None:
        try:
            ip = resolve_public_ip(self.host, self.port)
        except UnsafeAddressError as exc:
            self.result.https_available = (None, f"blocked_by_ssrf_guard: {exc}")
            return None
        except OSError as exc:
            self.result.https_available = (None, f"dns_resolution_failed: {exc}")
            return None

        # verified handshake
        try:
            der = self._handshake(ip, verify=True)
            self.result.https_available = (True, None)
            self.result.verification_failed = (False, None)
            return x509.load_der_x509_certificate(der)
        except ssl.SSLCertVerificationError as exc:
            self.result.verification_failed = (True, self._map_reason(exc))
        except (OSError, ssl.SSLError) as exc:
            self.result.https_available = (False, self._describe(exc))
            return None

        # unverified handshake, only to read the certificate as evidence
        try:
            der = self._handshake(ip, verify=False)
        except (OSError, ssl.SSLError) as exc:
            self.result.https_available = (False, self._describe(exc))
            return None
        self.result.https_available = (True, None)
        return x509.load_der_x509_certificate(der)

    def _handshake(self, ip: str, verify: bool) -> bytes:
        if verify:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, self.port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=self.host) as tls:
                der = tls.getpeercert(binary_form=True)
                if der is None:
                    raise ssl.SSLError("server presented no certificate")
                return der

    @staticmethod
    def _map_reason(exc: ssl.SSLCertVerificationError) -> str:
        reason = _VERIFY_CODE_REASONS.get(exc.verify_code)
        if reason:
            return reason
        return f"other: {exc.verify_message}"

    @staticmethod
    def _describe(exc: Exception) -> str:
        if isinstance(exc, TimeoutError):
            return "timeout"
        if isinstance(exc, ConnectionRefusedError):
            return "connection_refused"
        if isinstance(exc, ssl.SSLError):
            return f"tls_handshake_failed: {exc.reason or exc}"
        return f"{type(exc).__name__}: {exc}"