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