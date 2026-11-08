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

from constants.known_brands import KNOWN_BRANDS
from constants.suspicious_keywords import SUSPICIOUS_KEYWORDS
from analysis_result import URLAnalysisResult


class URLAnalyzer:
    TLD_EXTRACTOR = tldextract.TLDExtract(
        suffix_list_urls=()
    )

    normalized_url: str = None
    scheme: str = None
    domain: str = None

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
        domain = self.result.domain
        registered_domain = self.result.registered_domain

        # Use the registrable domain when available
        analysis_domain = registered_domain or domain

        domain_label = analysis_domain.split('.')[0]

        # 1. Structural characteristics
        self.result.domain_length = len(domain)
        self.result.subdomain_count = (
            len(self.result.subdomain.split('.'))
            if self.result.subdomain else 0
        )

        self.result.hyphen_count = domain.count('-')

        self.result.digit_count = sum(
            char.isdigit() for char in domain
        )

        self.result.unusually_long_domain = (
                self.result.domain_length > 50
        )

        self.result.excessive_hyphens = (
                self.result.hyphen_count >= 3
        )

        self.result.high_digit_count = (
                self.result.digit_count >= 5
        )

        # 2. IP address detection
        try:
            ipaddress.ip_address(domain)
            self.result.uses_ip_address = True

        except ValueError:
            self.result.uses_ip_address = False

        # 3. Unicode and Punycode inspection
        self.result.uses_punycode = 'xn--' in domain.lower()

        try:
            unicode_domain = domain.encode(
                'ascii'
            ).decode('idna')

        except UnicodeError:
            unicode_domain = domain

        self.result.unicode_domain = unicode_domain

        scripts = set()

        for char in unicode_domain:

            if not char.isalpha():
                continue

            unicode_name = unicodedata.name(char, '')

            for script in (
                    'LATIN',
                    'CYRILLIC',
                    'GREEK',
                    'HEBREW',
                    'ARABIC',
                    'HIRAGANA',
                    'KATAKANA',
                    'CJK',
                    'HANGUL'
            ):

                if script in unicode_name:
                    scripts.add(script)
                    break

        self.result.unicode_scripts = sorted(scripts)

        self.result.mixed_unicode_scripts = len(scripts) > 1

        self.result.confusable_characters_detected = (
            confusables.is_dangerous(
                unicode_domain,
                preferred_aliases=['latin']
            )
        )

        # 4. Typosquatting detection
        for brand in self.KNOWN_BRANDS:

            similarity = fuzz.ratio(
                domain_label,
                brand
            )

            if similarity >= 80 and domain_label != brand:
                self.result.typosquatting_detected = True

                self.result.typosquatting_brands.append(
                    brand
                )

            # Generated variant comparison
            variants = self._generate_domain_variants(brand)

            if domain_label in variants and domain_label != brand:

                self.result.generated_variant_match = True
                self.result.typosquatting_detected = True

                if brand not in self.result.typosquatting_brands:
                    self.result.typosquatting_brands.append(brand)

        # 5. Brand placement detection
        subdomain = self.result.subdomain or ''

        for brand in self.KNOWN_BRANDS:

            if brand in subdomain.split('.'):
                self.result.brand_in_subdomain = True
                self.result.brands_in_subdomain.append(brand)

            if brand in (self.result.decoded_path or '').lower():
                self.result.brand_in_path = True
                self.result.brands_in_path.append(brand)

        # 6. Suspicious keyword detection
        searchable_text = ' '.join([
            subdomain,
            domain,
            self.result.decoded_path or ''
        ]).lower()

        self.result.suspicious_keywords = [
            keyword
            for keyword in self.SUSPICIOUS_KEYWORDS
            if keyword in searchable_text
        ]

        # 7. High-risk TLD detection
        self.result.high_risk_tld = (
                self.result.public_suffix in self.HIGH_RISK_TLDS
        )

        # 8. Unusual port detection
        self.result.unusual_port = (
                self.result.port is not None
        )

        # 9. Shannon entropy
        self.result.domain_entropy = self._calculate_entropy(
            domain_label
        )

        self.result.high_domain_entropy = (
                self.result.domain_entropy >= 3.5
                and len(domain_label) >= 12
        )

    def _generate_domain_variants(self, brand: str) -> set[str]:
        variants = set()

        # Character omissions
        for i in range(len(brand)):
            variants.add(brand[:i] + brand[i + 1:])

        # Adjacent character transpositions
        for i in range(len(brand) - 1):

            variant = list(brand)

            variant[i], variant[i + 1] = (
                variant[i + 1],
                variant[i]
            )

            variants.add(''.join(variant))

        # Repeated characters
        for i in range(len(brand)):
            variants.add(
                brand[:i] + brand[i] + brand[i:]
            )

        # Keyboard adjacent substitutions
        for i, char in enumerate(brand):

            for adjacent in self.KEYBOARD_ADJACENCY.get(char, ''):

                variants.add(
                    brand[:i] + adjacent + brand[i + 1:]
                )

        return variants

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

    @staticmethod
    def _calculate_entropy(value: str) -> float:
        if not value:
            return 0.0

        entropy = 0.0

        for char in set(value):

            probability = value.count(char) / len(value)

            entropy -= probability * math.log2(probability)

        return round(entropy, 4)
