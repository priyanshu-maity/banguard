from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse
from difflib import SequenceMatcher
import ipaddress
import socket
import httpx


@dataclass
class URLAnalysisResult:
    normalized_url: str = None
    domain: str = None
    registered_domain: str | None = None

    ip_addresses: list[str] = field(default_factory=list)
    dns_records: list[str] = field(default_factory=list)

    # Domain characteristics
    unusually_long_domain: bool = False
    excessive_hyphens: bool = False
    high_digit_count: bool = False
    uses_ip_address: bool = False

    # Brand impersonation
    brand_impersonation: bool = False
    impersonated_brands: list[str] = field(default_factory=list)

    # DNS characteristics
    non_public_ip_resolution: bool = False
    dns_resolution_failed: bool = False

    # Redirect characteristics
    redirect_chain: list[str] = field(default_factory=list)
    final_url: str | None = None
    redirect_loop_detected: bool = False
    cross_domain_redirect: bool = False

    # Threat intelligence
    threat_matches: list[dict] = field(default_factory=list)
    threat_intelligence_match: bool = False


class URLAnalyzer:

    KNOWN_BRANDS = [
        'google',
        'microsoft',
        'amazon',
        'paypal',
        'facebook',
        'apple'
    ]

    def __init__(self, url: str, threat_intel_lookup=None):
        self.url = url
        self.threat_intel_lookup = threat_intel_lookup

        self.result = URLAnalysisResult()

    def analyze(self) -> URLAnalysisResult:
        self._normalize_url()
        self._inspect_domain()
        self._check_dns()
        self._inspect_redirects()
        self._check_threat_intelligence()

        return self.result

    def _normalize_url(self):
        parsed = urlparse(self.url)

        if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Invalid URL')

        self.result.normalized_url = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or '/',
            parsed.params,
            parsed.query,
            ''
        ))

        self.result.domain = parsed.hostname.lower()

    def _inspect_domain(self):
        domain = self.result.domain

        self.result.unusually_long_domain = len(domain) > 50

        self.result.excessive_hyphens = domain.count('-') >= 3

        self.result.high_digit_count = sum(
            char.isdigit() for char in domain
        ) >= 5

        try:
            ipaddress.ip_address(domain)
            self.result.uses_ip_address = True

        except ValueError:
            self.result.uses_ip_address = False

        # Basic brand impersonation check
        domain_name = domain.split('.')[0]

        for brand in self.KNOWN_BRANDS:

            similarity = SequenceMatcher(
                None,
                domain_name,
                brand
            ).ratio()

            if similarity >= 0.8 and domain_name != brand:
                self.result.brand_impersonation = True
                self.result.impersonated_brands.append(brand)

    def _check_dns(self):
        domain = self.result.domain

        try:
            records = socket.getaddrinfo(
                domain,
                None,
                type=socket.SOCK_STREAM
            )

            addresses = list(set(
                record[4][0] for record in records
            ))

            self.result.ip_addresses = addresses

            for address in addresses:

                ip = ipaddress.ip_address(address)

                if not ip.is_global:
                    self.result.non_public_ip_resolution = True

        except socket.gaierror:
            self.result.dns_resolution_failed = True

    def _inspect_redirects(self):
        current_url = self.result.normalized_url
        visited = set()

        self.result.redirect_chain.append(current_url)

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=5,
                trust_env=False
            ) as client:

                for _ in range(5):
                    if current_url in visited:
                        self.result.redirect_loop_detected = True
                        break

                    visited.add(current_url)

                    response = client.get(
                        current_url,
                        headers={'User-Agent': 'URLAnalyzer/1.0'}
                    )

                    if response.status_code not in (
                        301, 302, 303, 307, 308
                    ):
                        break

                    location = response.headers.get('location')

                    if not location:
                        break

                    current_url = str(
                        httpx.URL(current_url).join(location)
                    )

                    self.result.redirect_chain.append(current_url)

                self.result.final_url = current_url

                initial_domain = self.result.domain
                final_domain = urlparse(current_url).hostname

                if final_domain and final_domain != initial_domain:
                    self.result.cross_domain_redirect = True

        except httpx.HTTPError:
            pass

    def _check_threat_intelligence(self):
        if not self.threat_intel_lookup:
            return

        matches = self.threat_intel_lookup(
            self.result.domain
        )

        self.result.threat_matches = matches or []

        self.result.threat_intelligence_match = bool(
            self.result.threat_matches
        )
