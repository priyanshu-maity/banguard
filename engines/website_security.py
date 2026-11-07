from dataclasses import dataclass, field
from ipaddress import ip_address
from socket import getaddrinfo, SOCK_STREAM
from urllib.parse import urlsplit


@dataclass
class WebsiteSecurityResult:
    publicly_resolvable: bool | None = None
    resolved_ips: list[str] = field(default_factory=list)
    security_headers: dict[str, bool | None] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    error: str | None = None


def is_public_ip(address: str) -> bool:
    try:
        return ip_address(address).is_global
    except ValueError:
        return False

