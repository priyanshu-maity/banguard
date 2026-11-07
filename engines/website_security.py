from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from core.schema import AnalysisResult, AnalysisStatus
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

def _generate_header_findings(header_results: dict[str, bool | None],) -> list[SecurityFinding]:
    """Generate findings for missing security headers."""

    findings = []

    for header_name, present in header_results.items():
        if present is not False:
            continue

        details = SECURITY_HEADERS[header_name]

        findings.append(
            SecurityFinding(
                title=f"Missing {details['title']} header",
                severity=details["severity"],
                evidence=(
                    f"The HTTP response did not contain "
                    f"the {header_name} header."
                ),
                impact=details["impact"],
                remediation=details["remediation"],
            )
        )

    return findings


def analyze_website_security(url: str, investigation_id: str,) -> AnalysisResult[WebsiteSecurityResult]:
    """
    Perform the MVP website security analysis.

    1. Resolve and validate the initial hostname.
    2. Safely fetch the website using the existing fetcher.
    3. Inspect the final HTTP response headers.
    4. Generate findings for missing security headers.
    """

    result = WebsiteSecurityResult()

    try:
        parsed_url = urlsplit(url)

        if not parsed_url.hostname:
            raise ValueError("URL does not contain a hostname.")

        hostname = normalise_hostname(parsed_url.hostname)
        result.resolved_ips = resolve_public_ips(hostname)
        result.publicly_resolvable = True
        result.checks_completed.append("public_resolvability")

        fetched_page = safe_fetch(url, first_hop_ips=result.resolved_ips,)

        result.final_url = fetched_page.final_url
        result.status_code = fetched_page.status_code
        result.checks_completed.append("http_fetch")

        final_scheme = urlsplit(fetched_page.final_url).scheme
        result.security_headers = _check_security_headers(fetched_page.headers, is_https=(final_scheme == "https"),)
        result.findings.extend(_generate_header_findings(result.security_headers))
        result.checks_completed.append("security_headers")

        result.limitations.extend([
            "Only HTTP response headers were inspected. "
            "The response body and page content were not analysed.",
            "Security header checks verify presence only. "
            "They do not validate the quality of individual directives.",
            "A website passing these checks is not guaranteed to be safe.",
        ])

        return AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.COMPLETED, data=result,)

    except NonPublicAddressError as error:
        result.publicly_resolvable = False
        result.error = str(error)

        result.checks_completed.append("public_resolvability")

        return AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED, data=result, error=str(error),)

    except ResolutionError as error:
        result.error = f"DNS resolution failed: {error}"

        result.limitations.append(
            "Website fetching was skipped because public DNS "
            "resolution could not be completed."
        )

        return AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED, data=result, error=result.error,)

    except FetchError as error:
        result.error = error.message

        if error.hops:
            result.final_url = error.hops[-1].url

        result.limitations.append(
            "Website fetching or redirect validation did not complete. "
            "Security header checks were not completed."
        )

        return AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.PARTIAL, data=result, error=error.message,)

    except (ValueError, TypeError) as error:
        result.error = str(error)

        return AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED, data=result, error=str(error),)
