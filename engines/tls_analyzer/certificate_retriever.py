from urllib.parse import urlsplit
import socket
import ssl

from cryptography import x509


class CertificateRetriever:
    TIMEOUT = 5

    def __init__(self, hostname: str, port: int, destination_validator):
        self.hostname = hostname
        self.port = port
        self.destination_validator = destination_validator

        # Retrieved information
        self.certificate = None
        self.der_certificate = None

        # Connection information
        self.https_available = None
        self.verification_failed = None
        self.verification_reason = None
        self.connection_error = None

    def retrieve(self):
        # Validate destination before establishing a connection.
        safe_ips = self.destination_validator(
            self.hostname,
            self.port
        )

        verified_context = ssl.create_default_context()

        try:
            self.der_certificate = self._connect(
                safe_ips,
                verified_context
            )

            self.https_available = True
            self.verification_failed = False

        except ssl.SSLCertVerificationError as exc:
            self.verification_failed = True
            self.verification_reason = self._map_verification_error(exc)

            # Retry only to retrieve the certificate.
            unverified_context = ssl.create_default_context()
            unverified_context.check_hostname = False
            unverified_context.verify_mode = ssl.CERT_NONE

            try:
                self.der_certificate = self._connect(
                    safe_ips,
                    unverified_context
                )

                self.https_available = True

            except (OSError, ssl.SSLError) as retry_exc:
                self.https_available = False
                self.connection_error = str(retry_exc)

        except (OSError, ssl.SSLError) as exc:
            self.https_available = False
            self.verification_failed = False
            self.connection_error = str(exc)

        if self.der_certificate:
            self.certificate = x509.load_der_x509_certificate(
                self.der_certificate
            )

        return self

    def _connect(self, safe_ips, context) -> bytes:
        last_error = None

        for ip in safe_ips:
            try:
                with socket.create_connection(
                    (ip, self.port),
                    timeout=self.TIMEOUT
                ) as raw_socket:

                    with context.wrap_socket(
                        raw_socket,
                        server_hostname=self.hostname
                    ) as tls_socket:

                        return tls_socket.getpeercert(
                            binary_form=True
                        )

            except ssl.SSLCertVerificationError:
                raise

            except (OSError, ssl.SSLError) as exc:
                last_error = exc

        if last_error:
            raise last_error

        raise OSError('No validated IP addresses available')

    @staticmethod
    def _map_verification_error(exc):
        message = exc.verify_message.lower()

        if 'expired' in message:
            return 'expired'

        if 'not yet valid' in message:
            return 'not_yet_valid'

        if 'hostname' in message or 'ip address mismatch' in message:
            return 'hostname_mismatch'

        if 'self-signed' in message:
            return 'self_signed'

        if 'issuer' in message or 'unable to get' in message:
            return 'unknown_issuer'

        return 'unknown'
