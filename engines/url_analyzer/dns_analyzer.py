from datetime import datetime, timezone

import dns.resolver
import whois

from .analysis_result import URLAnalysisResult


class DNSAnalyzer:
    def __init__(self, domain: str, result: URLAnalysisResult):
        self.domain = domain
        self.result = result

        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 5

    def analyze(self):
        self.result.domain_exists = self._check_domain_existence()

        if self.result.domain_exists[0] is not True:
            self.result.missing_a_record = (None, None)
            self.result.missing_mx_on_impersonating_domain = (None, None)
            self.result.newly_registered_domain = (None, None)
            return

        self._check_a_records()
        self._check_mx_records()
        self._check_domain_age()

    def _check_domain_existence(self) -> tuple[bool | None, str | None]:
        try:
            self.resolver.resolve(self.domain, 'A')
            return True, f'Domain exists: {self.domain}'

        except dns.resolver.NXDOMAIN:
            return False, f'Domain does not exist: {self.domain}'

        except dns.resolver.NoAnswer as error:
            if error.response and error.response.rcode() == dns.rcode.NOERROR:
                return True, f'Domain exists but has no A record: {self.domain}'

            return None, 'Could not determine domain existence'

        except (dns.exception.DNSException, OSError):
            return None, 'DNS resolution failed'

    def _check_a_records(self):
        has_records, records = self._resolve_records('A')

        self.result.missing_a_record = (
            None if has_records is None else not has_records,
            None if has_records is None or has_records else (
                f'No A records found for {self.domain}'
            )
        )

    def _check_mx_records(self):
        if not self._is_brand_impersonating():
            self.result.missing_mx_on_impersonating_domain = (False, None)
            return

        has_records, records = self._resolve_records('MX')

        self.result.missing_mx_on_impersonating_domain = (
            None if has_records is None else not has_records,
            None if has_records is None or has_records else (
                f'No MX records found for brand impersonating domain {self.domain}'
            )
        )

    def _resolve_records(self, record_type: str) -> tuple[bool | None, list[str]]:
        try:
            answers = self.resolver.resolve(self.domain, record_type)

            records = [str(answer) for answer in answers]

            return True, records

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False, []

        except (dns.exception.DNSException, OSError):
            return None, []

    def _is_brand_impersonating(self) -> bool:
        return (
            self.result.typosquatting_detected[0]
            or self.result.brand_in_subdomain[0]
        )

    def _check_domain_age(self):
        creation_date = self._get_creation_date()

        if creation_date is None:
            self.result.newly_registered_domain = (None, None)
            return

        age_days = self._calculate_domain_age(creation_date)

        if age_days is None:
            self.result.newly_registered_domain = (None, None)
            return

        self.result.newly_registered_domain = (
            age_days < 30,
            age_days
        )

    def _get_creation_date(self) -> datetime | None:
        try:
            domain_info = whois.whois(self.domain)

            creation_date = domain_info['creation_date']

            if creation_date is None:
                return None

            # WHOIS can return multiple creation dates
            if isinstance(creation_date, list):
                dates = [
                    date for date in creation_date
                    if isinstance(date, datetime)
                ]

                if not dates:
                    return None

                creation_date = min(dates)

            if not isinstance(creation_date, datetime):
                return None

            # Handle timezone-naive dates
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            return creation_date

        except Exception:
            return None

    def _calculate_domain_age(self, creation_date: datetime) -> int | None:
        current_date = datetime.now(timezone.utc)

        age = current_date - creation_date

        if age.days < 0:
            return None

        return age.days