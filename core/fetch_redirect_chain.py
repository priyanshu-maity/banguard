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


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-verified IP, but still verifies the certificate
    against the original hostname (SNI and hostname check)."""

    def __init__(self, hostname: str, port: int, pinned_ip: str, timeout: float):
        self._tls_context = ssl.create_default_context()
        super().__init__(
            hostname, port, timeout=timeout, context=self._tls_context
        )
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout
        )
        try:
            self.sock = self._tls_context.wrap_socket(
                sock, server_hostname=self.host
            )
        except Exception:
            sock.close()
            raise

def _request_once(scheme: str, hostname: str, port: int, ips: list[str], target: str, hop: int, hops: list[RedirectHop],) -> tuple[int, dict[str, str]]:
    """Send one GET to a verified IP and read only the status and headers."""
    connection_class = (
        _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    )
    last_error: Exception | None = None

    for ip in ips:
        connection = connection_class(hostname, port, ip, REQUEST_TIMEOUT_SECONDS)
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()

            headers: dict[str, str] = {}
            for name, value in response.getheaders():
                key = name.lower()
                headers[key] = f"{headers[key]}, {value}" if key in headers else value

            return response.status, headers

        except ssl.SSLError as error:
            raise FetchError(
                "tls",
                f"TLS connection to {hostname} failed: {error}",
                hop,
                hops,
            ) from error
        except (OSError, http.client.HTTPException) as error:
            last_error = error
        finally:
            connection.close()

    raise FetchError(
        "connect", f"Could not connect to {hostname}: {last_error}", hop, hops
    )


def safe_fetch(url: str, first_hop_ips: list[str] | None = None) -> FetchedPage:
    """Fetch a URL's headers, following redirects manually and safely.

    Every hop is resolved, checked for public addresses and connected to by
    IP, so a redirect cannot lead us to an internal address and DNS cannot
    change between the check and the connection (DNS rebinding).

    first_hop_ips lets a caller that has already verified the first hostname
    reuse those IPs; otherwise the first hop is resolved here.

    Only the status line and headers are read, never the response body.
    Raises FetchError on any failure.
    """
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    current_url = url
    hops: list[RedirectHop] = []