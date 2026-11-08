from urllib.parse import urlsplit, urlunsplit

from core.fetch_redirect_chain import safe_fetch
from target_resolver import ResolvedTarget
from website_security_result import WebsiteSecurityResult


def _without_query(url: str) -> str:
    """Query strings often carry tokens, so they stay out of the report."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _bare_host(url_or_host: str, is_url: bool) -> str:
    host = (urlsplit(url_or_host).hostname if is_url else url_or_host) or ""
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


class PageFetcher:
    """Fetches the page through the project's safe fetcher and records what came back."""

    def __init__(self, target: ResolvedTarget, result: WebsiteSecurityResult):
        self.target = target
        self.result = result

    def fetch(self):
        page = safe_fetch(self.target.url, first_hop_ips=self.target.ips)  # raises FetchError
        final_url = _without_query(page.final_url)
        status = page.status_code if isinstance(page.status_code, int) else None

        self.result.page_fetched = (True, final_url)
        self.result.error_response_received = (None if status is None else status >= 400, status)
        self.result.served_over_http = (urlsplit(page.final_url).scheme.lower() == "http", final_url)

        final_host = _bare_host(page.final_url, is_url=True)
        self.result.final_host_differs = (final_host != _bare_host(self.target.hostname, is_url=False), final_host)

        return page