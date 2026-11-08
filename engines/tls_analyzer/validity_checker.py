import ipaddress
from datetime import datetime, timezone

from cryptography import x509

from .analysis_result import TLSAnalysisResult


class ValidityChecker:
    NEW_CERTIFICATE_DAYS = 7

    def __init__(self, certificate: x509.Certificate, host: str, result: TLSAnalysisResult, now: datetime | None = None):
        self.certificate = certificate
        self.host = host.lower().rstrip(".")
        self.result = result
        self.now = now or datetime.now(timezone.utc)

    def check(self) -> None:
        self._check_dates()
        self._check_hostname()

    def _check_dates(self) -> None:
        not_before = self.certificate.not_valid_before_utc
        not_after = self.certificate.not_valid_after_utc

        days_remaining = int((not_after - self.now).total_seconds() // 86400)
        self.result.certificate_expired = (self.now > not_after, days_remaining)

        self.result.certificate_not_yet_valid = (self.now < not_before, not_before.isoformat())

        age_days = (self.now - not_before).days
        self.result.newly_issued_certificate = (0 <= age_days < self.NEW_CERTIFICATE_DAYS, age_days)

    def _check_hostname(self) -> None:
        dns_names, ip_names = self._subject_alt_names()
        try:
            ipaddress.ip_address(self.host)
            matched = self.host in ip_names
        except ValueError:
            matched = any(self._dns_match(self.host, name) for name in dns_names)

        self.result.hostname_mismatch = (not matched, dns_names + ip_names)

    def _subject_alt_names(self) -> tuple[list[str], list[str]]:
        try:
            san = self.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            return [], []
        dns_names = [name.lower().rstrip(".") for name in san.get_values_for_type(x509.DNSName)]
        ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        return dns_names, ip_names

    @staticmethod
    def _dns_match(host: str, pattern: str) -> bool:
        if not pattern.startswith("*."):
            return host == pattern
        suffix = pattern[1:]
        if suffix.count(".") < 2:
            return False
        if not host.endswith(suffix):
            return False
        label = host[: -len(suffix)]
        return bool(label) and "." not in label
