from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from core.schemas import AnalysisResult, AnalysisStatus
from core.network_safety import (
    NonPublicAddressError,
    ResolutionError,
    normalise_hostname,
    resolve_public_ips,
)
from core.fetch_redirect_chain import FetchError, safe_fetch


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


SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security (HSTS)",
        "severity": Severity.MEDIUM,
        "impact": (
            "Without HSTS, browsers may be more vulnerable to "
            "protocol downgrade and certain man-in-the-middle attacks."
        ),
        "remediation": (
            "Configure Strict-Transport-Security with an appropriate "
            "max-age value."
        ),
    },
    "content-security-policy": {
        "title": "Content Security Policy (CSP)",
        "severity": Severity.MEDIUM,
        "impact": (
            "Without a Content Security Policy, browsers have fewer "
            "restrictions on the sources from which content can load."
        ),
        "remediation": (
            "Configure a Content-Security-Policy that restricts "
            "trusted content sources and script execution."
        ),
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "impact": (
            "Without this header, some browsers may perform MIME "
            "type sniffing."
        ),
        "remediation": (
            "Set X-Content-Type-Options to nosniff."
        ),
    },
    "x-frame-options": {
        "title": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "impact": (
            "Without an appropriate framing policy, the website "
            "may be more exposed to clickjacking."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or configure "
            "an appropriate frame-ancestors directive in CSP."
        ),
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "severity": Severity.LOW,
        "impact": (
            "Without a referrer policy, URLs or other referrer "
            "information may be shared more broadly than intended."
        ),
        "remediation": (
            "Configure a suitable Referrer-Policy, such as "
            "strict-origin-when-cross-origin."
        ),
    },
    "permissions-policy": {
        "title": "Permissions-Policy",
        "severity": Severity.LOW,
        "impact": (
            "Without this header, browser features are not explicitly "
            "restricted through Permissions-Policy."
        ),
        "remediation": (
            "Configure Permissions-Policy to restrict browser "
            "features that the website does not need."
        ),
    },
}

def _check_security_headers(headers: dict[str, str], is_https: bool,) -> dict[str, bool | None]:
    """
    Check whether the six expected security headers are present.

    HSTS is not applicable to an HTTP response, so its value
    is None when the final URL uses HTTP.
    """

    results = {}

    for header_name in SECURITY_HEADERS:
        if header_name == "strict-transport-security" and not is_https:
            results[header_name] = None
            continue

        value = headers.get(header_name)
        results[header_name] = bool(value and value.strip())

    return results

