import ipaddress
import idna
from urllib.parse import urlparse, urlunparse

from analysis_result import URLAnalysisResult


class URLNormalizer:
    def __init__(self, url: str, result: URLAnalysisResult):
        self.url = url
        self.result = result

        self.normalized_url = None
        self.domain = None
        self.scheme = None

    def normalize(self) -> str:
        url = self._validate_url()
        parsed = urlparse(url)

        self._detect_userinfo(parsed)

        hostname = parsed.hostname.rstrip('.').lower()
        ascii_hostname = self._normalize_hostname(hostname)

        netloc = self._reconstruct_netloc(parsed, ascii_hostname)

        self.normalized_url = self._reconstruct_url(parsed, netloc)
        self.domain = hostname if self.result.uses_ip_address[0] else (
            idna.encode(hostname).decode('ascii')
        )
        self.scheme = parsed.scheme.lower()

        return self.normalized_url

    def _validate_url(self) -> str:
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

        return url

    def _detect_userinfo(self, parsed):
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

    def _normalize_hostname(self, hostname: str) -> str:
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

        return ascii_hostname

    def _reconstruct_netloc(self, parsed, ascii_hostname: str) -> str:
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

        return ascii_hostname + port_suffix

    def _reconstruct_url(self, parsed, netloc: str) -> str:
        return urlunparse((
            parsed.scheme.lower(),
            netloc,
            parsed.path or '/',
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
