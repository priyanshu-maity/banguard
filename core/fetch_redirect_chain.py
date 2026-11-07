import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from core.network_safety import (
    NonPublicAddressError,
    ResolutionError,
    normalise_hostname,
    resolve_public_ips,
)

REQUEST_TIMEOUT_SECONDS = 5
TOTAL_TIMEOUT_SECONDS = 20
MAX_REDIRECTS = 5
ALLOWED_PORTS = {80, 443, 8080, 8443}
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
USER_AGENT = "BanGuard-SecurityCheck/1.0"


@dataclass
class RedirectHop:
    url: str
    status_code: int
    resolved_ips: list[str]


@dataclass
class FetchedPage:
    final_url: str
    status_code: int
    headers: dict[str, str]
    resolved_ips: list[str]
    hops: list[RedirectHop]

    @property
    def redirect_count(self) -> int:
        return len(self.hops) - 1


class FetchError(Exception):
    def __init__(self, kind: str, message: str, hop: int = 0, hops: list[RedirectHop] | None = None,):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.hop = hop
        self.hops = hops if hops is not None else []


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-verified IP instead of resolving the hostname again."""

    def __init__(self, hostname: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout
        )