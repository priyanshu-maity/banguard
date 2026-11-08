from urllib.parse import urlparse, urlunparse, unquote
import ipaddress
import idna
import httpx
import tldextract
import math
import unicodedata
import dns.resolver
import dns.exception
from rapidfuzz import fuzz
from confusable_homoglyphs import confusables

from analysis_result import URLAnalysisResult
from domain_inspector import DomainInspector


class URLAnalyzer:
    TLD_EXTRACTOR = tldextract.TLDExtract(
        suffix_list_urls=()
    )

    def __init__(self, url: str, threat_intel_lookup=None):
        self.url = url
        self.threat_intel_lookup = threat_intel_lookup

        self.normalized_url = None
        self.scheme = None
        self.domain = None

        self.subdomain = None
        self.registered_domain = None
        self.public_suffix = None

        self.result = URLAnalysisResult()

    def analyze(self) -> URLAnalysisResult:
        self._normalize_url()
        self._inspect_domain()
        self._check_dns()
        self._inspect_redirects()
        self._check_threat_intelligence()

        return self.result

    def _normalize_url(self):
        url = self.url.strip()

        if not url:
            raise ValueError('URL cannot be empty')

        if any(char.isspace() or ord(char) < 32 for char in url):
            raise ValueError('URL contains invalid whitespace or control characters')

        if '://' not in url:
            raise ValueError('URL must include a scheme (http:// or https://)')

        parsed = urlparse(url)

        if parsed.scheme.lower() not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS URLs are supported')

        if not parsed.hostname:
            raise ValueError('URL must contain a hostname')

        # Detect embedded credentials
        self.result.has_userinfo = (
            self.result.has_userinfo[0] or parsed.username is not None or parsed.password is not None,
            [
                item for item, present in (
                ('username', parsed.username is not None),
                ('password', parsed.password is not None)
            )
                if present
            ]
        )

        hostname = parsed.hostname.rstrip('.').lower()

        # Detect IP address hosts and convert IDNs to Punycode
        try:
            ip = ipaddress.ip_address(hostname)

            ascii_hostname = str(ip)
            self.result.uses_ip_address = (True, ascii_hostname)

        except ValueError:
            try:
                ascii_hostname = idna.encode(hostname).decode('ascii')
                self.result.uses_ip_address = (False, None)

            except idna.IDNAError:
                raise ValueError('Invalid internationalised domain name')

        # Preserve IPv6 brackets
        if ':' in ascii_hostname:
            ascii_hostname = f'[{ascii_hostname}]'

        # Preserve an explicitly supplied port without analysing it
        authority = parsed.netloc.rsplit('@', 1)[-1]

        if authority.startswith('['):
            closing_bracket = authority.find(']')
            port_suffix = authority[closing_bracket + 1:]

        elif authority.count(':') == 1:
            port_suffix = authority[authority.rfind(':'):]

        else:
            port_suffix = ''

        netloc = ascii_hostname + port_suffix

        # Reconstruct normalized URL without embedded credentials
        normalized_url = urlunparse((
            parsed.scheme.lower(),
            netloc,
            parsed.path or '/',
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        self.normalized_url = normalized_url
        self.domain = hostname if self.result.uses_ip_address[0] else (
            idna.encode(hostname).decode('ascii')
        )

        self.scheme = parsed.scheme.lower()

    def _inspect_domain(self):
        parsed = urlparse(self.normalized_url)
        self.path = parsed.path or '/'

        if self.result.uses_ip_address[0]:
            return

        inspector = DomainInspector(
            domain=self.domain,
            path=self.path,
            result=self.result
        )

        self.result = inspector.inspect()

        self.subdomain = inspector.subdomain
        self.registered_domain = inspector.registered_domain
        self.public_suffix = inspector.public_suffix

    def _check_dns(self):
        domain = self.result.domain

        record_types = (
            'A',
            'AAAA',
            'MX',
            'NS',
            'TXT',
            'CNAME'
        )

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        addresses = set()
        nameservers = []

        for record_type in record_types:

            try:
                answer = resolver.resolve(
                    domain,
                    record_type,
                    lifetime=5
                )

                # Store TTL values
                ttl = answer.rrset.ttl

                self.result.dns_ttls.setdefault(
                    record_type, []
                ).append(ttl)

                # Detect unusually low TTL
                if ttl < 300:
                    self.result.low_dns_ttl = True

                # Store DNS records
                for record in answer:

                    record_value = record.to_text()

                    self.result.dns_records.append(
                        f'{record_type}: {record_value}'
                    )

                    # Extract IP addresses
                    if record_type in ('A', 'AAAA'):
                        addresses.add(record_value)

                    # Collect nameservers
                    elif record_type == 'NS':
                        nameservers.append(
                            record_value.rstrip('.').lower()
                        )

            except dns.resolver.NoAnswer:
                continue

            except dns.resolver.NXDOMAIN:
                self.result.dns_resolution_failed = True
                break

            except dns.exception.DNSException:
                continue

        # Store resolved IP addresses
        self.result.ip_addresses = sorted(addresses)

        # Detect missing MX records
        self.result.missing_mx_record = not any(
            record.startswith('MX: ')
            for record in self.result.dns_records
        )

        # Check nameserver characteristics
        for nameserver in nameservers:

            try:
                ipaddress.ip_address(nameserver)

                self.result.unusual_nameservers.append(
                    nameserver
                )

                continue

            except ValueError:
                pass

            if (
                    '.' not in nameserver or
                    '_' in nameserver or
                    'xn--' in nameserver
            ):
                self.result.unusual_nameservers.append(
                    nameserver
                )

        # Check whether resolved IPs are publicly routable
        for address in self.result.ip_addresses:

            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                self.result.non_public_ip_resolution = True

        # No usable A or AAAA resolution
        if not self.result.ip_addresses:
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
