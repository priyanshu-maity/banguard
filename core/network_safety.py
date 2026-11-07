import re
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from socket import SOCK_STREAM, gaierror, getaddrinfo


_NAT64_NETWORK = ip_network("64:ff9b::/96")
_HOSTNAME_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

class ResolutionError(Exception):
    """Raised when a hostname cannot be resolved successfully."""


class NonPublicAddressError(Exception):
    """Raised when a hostname resolves to a non-public IP address."""

    def __init__(self, address: str):
        self.address = address
        super().__init__(f"Non-public IP address detected: {address}")