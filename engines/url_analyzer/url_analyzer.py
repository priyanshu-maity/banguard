from urllib.parse import urlparse

from .analysis_result import URLAnalysisResult
from url_normalizer import URLNormalizer
from domain_inspector import DomainInspector
from dns_analyzer import DNSAnalyzer
from redirect_analyzer import RedirectAnalyzer


class URLAnalyzer:
    def __init__(self, url: str):
        self.url = url

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

        return self.result

    def _normalize_url(self):
        normalizer = URLNormalizer(self.url, self.result)

        self.normalized_url = normalizer.normalize()
        self.domain = normalizer.domain
        self.scheme = normalizer.scheme

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

        inspector.inspect()

        self.subdomain = inspector.subdomain
        self.registered_domain = inspector.registered_domain
        self.public_suffix = inspector.public_suffix

    def _check_dns(self):
        if self.registered_domain is None:
            return

        analyzer = DNSAnalyzer(self.registered_domain, self.result)
        analyzer.analyze()

    def _inspect_redirects(self):
        analyzer = RedirectAnalyzer(self.normalized_url, self.result)
        analyzer.analyze()
