import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.network_safety import normalise_hostname, resolve_public_ips
from .website_security_result import WebsiteSecurityResult

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_PORTS = (80, 443, 8080, 8443)
MAX_URL_LENGTH = 2048

_FORBIDDEN_CHARS = re.compile(r"[\\\s\x00-\x1f\x7f]")


class InvalidTargetError(ValueError):
    """The submitted URL is not something this module will analyse. The message is safe to show the user."""


@dataclass(frozen=True)
class ResolvedTarget:
    url: str  # the validated URL: pass this, and only this, to the fetcher
    hostname: str
    port: int | None
    ips: list[str]


class TargetResolver:
    def __init__(self, url: str, result: WebsiteSecurityResult):
        self.url = url
        self.result = result

    def resolve(self) -> ResolvedTarget:
        url = self._validated_url()
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise InvalidTargetError("Only http and https URLs can be analysed.")
        if not parsed.hostname:
            raise InvalidTargetError("URL does not contain a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise InvalidTargetError("URLs with embedded credentials are not analysed.")
        try:
            port = parsed.port
        except ValueError:
            raise InvalidTargetError("URL contains an invalid port.") from None
        if port is not None and port not in ALLOWED_PORTS:
            raise InvalidTargetError("Only standard web ports can be analysed.")

        hostname = normalise_hostname(parsed.hostname)
        ips = resolve_public_ips(hostname)  # raises NonPublicAddressError / ResolutionError

        self.result.publicly_resolvable = (True, list(ips))
        return ResolvedTarget(url=url, hostname=hostname, port=port, ips=list(ips))

    def _validated_url(self) -> str:
        if not isinstance(self.url, str):
            raise InvalidTargetError("URL must be a string.")
        url = self.url.strip()
        if not url or len(url) > MAX_URL_LENGTH:
            raise InvalidTargetError("URL is empty or too long.")
        if _FORBIDDEN_CHARS.search(url):
            raise InvalidTargetError("URL contains characters that are not allowed.")
        return url