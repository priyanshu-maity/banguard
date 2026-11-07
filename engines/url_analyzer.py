from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse
from difflib import SequenceMatcher
import ipaddress
import socket
import httpx


@dataclass
class URLAnalysisResult:
    normalized_url: str

    scheme: str | None = None
    hostname: str | None = None
    port: int | None = None
    path: str | None = None
    query: str | None = None

    errors: list[str] = field(default_factory=list)


class URLAnalyzer:
    def __init__(self, url: str):
        self.url = url
        self.result = URLAnalysisResult(normalized_url=url)

    def _normalize_url(self):
        url = self.url.strip()

        if not url:
            raise ValueError('URL cannot be empty')

        parsed = urlparse(url)

        if parsed.scheme.lower() not in ('http', 'https'):
            raise ValueError('Only HTTP and HTTPS URLs are supported')

        if not parsed.hostname:
            raise ValueError('URL must contain a hostname')

        if any(char.isspace() or ord(char) < 32 for char in url):
            raise ValueError('URL contains invalid whitespace or control characters')

    def inspect_url(self):
        ...
