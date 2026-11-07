
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

    def normalize_url(self):
        ...

    def inspect_url(self):
        ...
        