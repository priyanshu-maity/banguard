from dataclasses import dataclass, field
from ipaddress import ip_address
from socket import getaddrinfo, SOCK_STREAM
from urllib.parse import urlsplit


@dataclass
class WebsiteSecurityResult:
    url: str
    url_valid: bool | None = None
    publicly_resolvable: bool | None = None
    resolved_ips: list[str] = field(default_factory=list)
    error: str | None = None

def is_public_ip(address: str) -> bool:
    try:
        ip = ip_address(address)
        return ip.is_global
    except ValueError:
        return False
