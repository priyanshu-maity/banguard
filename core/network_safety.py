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


def normalise_hostname(hostname: str) -> str:
    """
    Normalise a hostname for DNS resolution.
    Supports ordinary domain names and IP address literals.
    """

    if not isinstance(hostname, str):
        raise ValueError("Hostname must be a string.")

    hostname = hostname.strip()

    if not hostname:
        raise ValueError("Hostname is empty.")
    if "%" in hostname:
        raise ValueError("Scoped IP addresses are not supported.")

    try:
        return ip_address(hostname).compressed
    except ValueError:
        pass

    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ValueError("Hostname is empty.")

    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"Invalid internationalised hostname: {error}") from error

    if len(hostname) > 253:
        raise ValueError("Hostname is too long.")

    labels = hostname.split(".")

    if any(not label for label in labels):
        raise ValueError("Hostname contains an empty label.")

    for label in labels:
        if not _HOSTNAME_LABEL_PATTERN.fullmatch(label):
            raise ValueError(f"Invalid hostname label: {label}")

    return hostname
