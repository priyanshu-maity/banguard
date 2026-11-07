from dataclasses import dataclass, field
from ipaddress import IPv6Address, ip_address, ip_network
from socket import getaddrinfo, SOCK_STREAM
from urllib.parse import urlsplit


_NAT64_NETWORK = ip_network("64:ff9b::/96")

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SecurityFinding:
    title: str
    severity: Severity
    evidence: str
    impact: str
    remediation: str


@dataclass
class WebsiteSecurityResult:
    publicly_resolvable: bool | None = None
    resolved_ips: list[str] = field(default_factory=list)

    final_url: str | None = None
    status_code: int | None = None
    security_headers: dict[str, bool | None] = field(default_factory=dict)

    findings: list[SecurityFinding] = field(default_factory=list)
    checks_completed: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    error: str | None = None


def normalise_hostname(hostname: str) -> str:
    hostname = hostname.strip().rstrip(".").lower()

    if not hostname:
        raise ValueError("Hostname is empty.")
    return hostname.encode("idna").decode("ascii")


def is_public_ip(address: str) -> bool:
    try:
        ip = ip_address(address.split("%")[0])
    except ValueError:
        return False

    if isinstance(ip, IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64_NETWORK:
            return False

    return ip.is_global and not ip.is_multicast


def check_public_resolvability(hostname: str) -> WebsiteSecurityResult:
    result = WebsiteSecurityResult()

    try:
        hostname = normalise_hostname(hostname)
        addresses = getaddrinfo(hostname, None, type=SOCK_STREAM)
        result.resolved_ips = list(
            dict.fromkeys(address[4][0] for address in addresses)
        )

        if not result.resolved_ips:
            raise ValueError("Hostname did not resolve to any IP address.")

    except (OSError, ValueError) as error:
        result.error = f"DNS resolution failed: {error}"
        result.limitations.append(
            "Network safety check could not be completed because DNS "
            "resolution failed."
        )
        return result

    for address in result.resolved_ips:
        if not is_public_ip(address):
            result.publicly_resolvable = False
            result.error = f"Non-public IP address detected: {address}"
            result.checks_completed.append("public_resolvability")
            return result

    result.publicly_resolvable = True
    result.checks_completed.append("public_resolvability")

    return result
