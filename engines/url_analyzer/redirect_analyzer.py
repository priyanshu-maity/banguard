import httpx
import socket
import ipaddress
import tldextract

from urllib.parse import urlparse, urljoin

from .analysis_result import URLAnalysisResult
from constants.url_shorteners import URL_SHORTENERS


class RedirectAnalyzer:
    MAX_HOPS = 5
    REDIRECT_CODES = {301, 302, 303, 307, 308}
    TLD_EXTRACTOR = tldextract.TLDExtract()

    def __init__(self, url: str, result: URLAnalysisResult):
        self.url = url
        self.result = result

        self.visited_urls = []
        self.cross_domain_destinations = []
        self.shortener_domains = []
        self.unsafe_addresses = []

        self.initial_domain = self._get_registered_domain(url)

    def analyze(self):
        with httpx.Client(
            follow_redirects=False,
            timeout=10,
            trust_env=False
        ) as client:

            current_url = self.url

            for _ in range(self.MAX_HOPS + 1):

                if not self._validate_destination(current_url):
                    break

                self.visited_urls.append(current_url)

                hostname = urlparse(current_url).hostname.lower()

                self._check_shortener(hostname)

                try:
                    response = client.get(current_url)

                except httpx.HTTPError:
                    break

                if response.status_code not in self.REDIRECT_CODES:
                    break

                location = response.headers.get('location')

                if not location:
                    break

                next_url = urljoin(current_url, location)

                self._check_cross_domain(next_url)

                self.visited_urls.append(
                    f'{response.status_code} -> {next_url}'
                )

                current_url = next_url

        self._populate_results()

    def _validate_destination(self, url: str) -> bool:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ('http', 'https'):
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        try:
            ipaddress.ip_address(hostname)

            addresses = [hostname]

        except ValueError:
            try:
                addresses = list({
                    item[4][0]
                    for item in socket.getaddrinfo(
                        hostname,
                        None,
                        type=socket.SOCK_STREAM
                    )
                })

            except OSError:
                return False

        if not addresses:
            return False

        for address in addresses:
            ip = ipaddress.ip_address(address)

            if ip.is_private or ip.is_loopback or ip.is_link_local:
                self.unsafe_addresses.append(
                    f'{hostname} -> {ip}'
                )
                return False

        return True

    def _check_cross_domain(self, url: str):
        destination_domain = self._get_registered_domain(url)

        if (
            destination_domain
            and destination_domain != self.initial_domain
            and destination_domain not in self.cross_domain_destinations
        ):
            self.cross_domain_destinations.append(destination_domain)

    def _check_shortener(self, hostname: str):
        if (
            hostname in URL_SHORTENERS
            and hostname not in self.shortener_domains
        ):
            self.shortener_domains.append(hostname)

    def _get_registered_domain(self, url: str) -> str:
        hostname = urlparse(url).hostname or ''

        extracted = self.TLD_EXTRACTOR(hostname)

        return extracted.top_domain_under_public_suffix

    def _populate_results(self):
        self.result.redirect_chain = (
            len(self.visited_urls) > 1,
            self.visited_urls
        )

        self.result.cross_domain_redirect = (
            bool(self.cross_domain_destinations),
            self.cross_domain_destinations
        )

        self.result.url_shortener_detected = (
            bool(self.shortener_domains),
            self.shortener_domains
        )

        self.result.ssrf_attempt_detected = (
            bool(self.unsafe_addresses),
            self.unsafe_addresses
        )