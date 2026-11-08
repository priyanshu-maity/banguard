
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from core.fetch_redirect_chain import FetchError, safe_fetch
from core.network_safety import (
    NonPublicAddressError,
    ResolutionError,
    normalise_hostname,
    resolve_public_ips,
)
from core.schema import AnalysisResult, AnalysisStatus


@dataclass
class SecurityFinding:
    title: str
    severity: str
    evidence: str
    impact: str
    remediation: str


@dataclass
class WebsiteSecurityResult:
    publicly_resolvable: bool = False
    resolved_ips: list[str] = field(default_factory=list)
    final_url: str | None = None
    status_code: int | None = None
    security_headers: dict[str, str | None] = field(default_factory=dict)
    findings: list[SecurityFinding] = field(default_factory=list)
    checks_completed: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    error: str | None = None


SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", "MEDIUM"),
    "content-security-policy": ("Missing Content Security Policy", "MEDIUM"),
    "x-content-type-options": ("Missing X-Content-Type-Options header", "LOW"),
    "x-frame-options": ("Missing X-Frame-Options header", "LOW"),
    "referrer-policy": ("Missing Referrer-Policy header", "LOW"),
    "permissions-policy": ("Missing Permissions-Policy header", "LOW"),
}

HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}

SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pass", "pwd", "current_password",
    "new_password", "username", "email", "user", "login",
    "cardnumber", "card_number", "cc-number", "cvv", "cvc",
    "otp", "verification_code", "security_code",
}

BRAND_KEYWORDS = {
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "netflix", "whatsapp",
    "linkedin", "outlook", "office365", "bank",
}

SUSPICIOUS_PAGE_TERMS = {
    "verify your account", "account suspended", "confirm your identity",
    "unusual activity", "payment failed", "update your payment",
    "account verification", "sign in to continue", "login to continue",
    "your account has been locked",
}

EXPLICIT_PHISHING_TERMS = {
    "example of a phishing page",
    "phishing page",
    "social engineering content example",
    "trick you into clicking",
    "does not actually originate from",
    "mimicking the site's look and feel",
}


def _hostname(url: str) -> str | None:
    try:
        hostname = urlsplit(url).hostname
        return normalise_hostname(hostname) if hostname else None
    except (ValueError, TypeError):
        return None


def _registrable_domain(hostname: str) -> str:
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname.lower()


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.current_form: dict | None = None
        self.title_parts: list[str] = []
        self.in_title = False
        self.text_parts: list[str] = []
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.external_scripts: list[str] = []
        self.external_iframes: list[str] = []
        self.meta_refreshes: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attributes = {key.lower(): value or "" for key, value in attrs}

        if tag == "title":
            self.in_title = True

        if tag == "form":
            self.current_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").lower(),
                "fields": [],
            }

        if tag == "input":
            name = attributes.get("name", "").lower()
            input_type = attributes.get("type", "text").lower()

            if input_type == "password":
                self.password_inputs += 1

            if input_type == "hidden":
                self.hidden_inputs += 1

            if self.current_form is not None:
                self.current_form["fields"].append({"name": name, "type": input_type})

        if tag == "button" and self.current_form is not None:
            self.current_form["fields"].append({
                "name": attributes.get("name", "").lower(),
                "type": "button",
            })

        if tag == "script" and attributes.get("src"):
            self.external_scripts.append(attributes["src"])

        if tag == "iframe" and attributes.get("src"):
            self.external_iframes.append(attributes["src"])

        if tag == "meta" and attributes.get("http-equiv", "").lower() == "refresh":
            self.meta_refreshes.append(attributes.get("content", ""))

    def handle_endtag(self, tag: str):
        if tag == "title":
            self.in_title = False

        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_data(self, data: str):
        if self.in_title:
            self.title_parts.append(data)

        self.text_parts.append(data)


def _add_finding(result: WebsiteSecurityResult, title: str, severity: str, evidence: str, impact: str, remediation: str):
    if any(finding.title == title for finding in result.findings):
        return

    result.findings.append(SecurityFinding(title, severity, evidence, impact, remediation))


def _analyse_html(result: WebsiteSecurityResult, page_url: str, body: bytes):
    html = body.decode("utf-8", errors="replace")
    parser = _PageParser()

    try:
        parser.feed(html)
        parser.close()
    except Exception:
        result.limitations.append("HTML parsing was incomplete.")

    page_hostname = _hostname(page_url)
    if not page_hostname:
        return

    page_domain = _registrable_domain(page_hostname)
    page_text = " ".join(parser.text_parts).lower()
    title = " ".join(parser.title_parts).strip().lower()

    matched_phishing_terms = sorted(term for term in EXPLICIT_PHISHING_TERMS if term in page_text or term in title)

    if matched_phishing_terms:
        _add_finding(
            result,
            "Explicit phishing or social-engineering indicators",
            "MEDIUM",
            f"Detected explicit phishing-related language: {', '.join(matched_phishing_terms)}.",
            "The page discusses phishing or social-engineering behaviour. This language alone does not establish that the page performs phishing.",
            "Review the page context and verify whether it is educational material or an actual credential-harvesting page.",
        )

    sensitive_forms = []

    for form in parser.forms:
        sensitive_fields = [
            item for item in form["fields"]
            if item["name"] in SENSITIVE_FIELD_NAMES or item["type"] == "password"
        ]

        if sensitive_fields:
            sensitive_forms.append((form, sensitive_fields))

    if sensitive_forms:
        _add_finding(
            result,
            "Page collects sensitive credentials",
            "HIGH",
            f"Detected {len(sensitive_forms)} form(s) containing password, account, payment, or verification-related fields.",
            "The page contains forms designed to collect credentials or sensitive information.",
            "Verify the website owner and ensure sensitive data is submitted only to a legitimate, trusted service.",
        )

    for form, sensitive_fields in sensitive_forms:
        action = form["action"].strip()

        if not action:
            continue

        destination = urljoin(page_url, action)
        destination_hostname = _hostname(destination)

        if not destination_hostname:
            continue

        if _registrable_domain(destination_hostname) != page_domain:
            _add_finding(
                result,
                "Sensitive form submits to an external domain",
                "HIGH",
                f"A form containing sensitive fields submits to {destination_hostname}, while the page is hosted on {page_hostname}.",
                "Credentials or sensitive information may be sent to an unrelated domain.",
                "Verify that the external destination is an explicitly trusted authentication or payment provider.",
            )

    matched_brands = sorted(brand for brand in BRAND_KEYWORDS if brand in page_text or brand in title)

    if matched_brands and (sensitive_forms or parser.password_inputs):
        _add_finding(
            result,
            "Brand references combined with credential collection",
            "MEDIUM",
            f"Page references {', '.join(matched_brands)} and contains sensitive input fields.",
            "The combination may indicate an impersonation or credential-harvesting page.",
            "Verify the domain against the official website of the referenced brand.",
        )

    matched_terms = sorted(term for term in SUSPICIOUS_PAGE_TERMS if term in page_text)

    if matched_terms:
        _add_finding(
            result,
            "Suspicious account or payment language",
            "LOW",
            f"Detected phrases: {', '.join(matched_terms[:5])}.",
            "Urgent account or payment language can be used to pressure visitors into disclosing information.",
            "Verify account warnings through the official website or application.",
        )

    if parser.password_inputs and not sensitive_forms:
        _add_finding(
            result,
            "Password field outside a detected form",
            "MEDIUM",
            f"Detected {parser.password_inputs} password input field(s), but no enclosing form was parsed.",
            "The page contains password-entry elements whose submission behaviour could not be established.",
            "Avoid entering credentials until the page and its scripts are independently verified.",
        )

    if parser.meta_refreshes:
        _add_finding(
            result,
            "HTML meta-refresh redirect detected",
            "LOW",
            f"Detected {len(parser.meta_refreshes)} meta-refresh directive(s).",
            "The page may redirect visitors after loading.",
            "Check the destination and verify that it belongs to the expected service.",
        )

    if parser.external_iframes:
        _add_finding(
            result,
            "External iframe content detected",
            "LOW",
            f"Detected {len(parser.external_iframes)} iframe(s) with external sources.",
            "External embedded content can display content controlled by another website.",
            "Verify that embedded content comes from trusted providers.",
        )

    result.checks_completed.append("HTML content inspection")


def analyze_website_security(url: str, investigation_id: str) -> AnalysisResult:
    result = WebsiteSecurityResult()

    try:
        parts = urlsplit(url)

        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("A valid HTTP or HTTPS URL is required.")

        hostname = normalise_hostname(parts.hostname)
        result.resolved_ips = resolve_public_ips(hostname)
        result.publicly_resolvable = True
        result.checks_completed.append("Public DNS resolution")

        fetched_page = safe_fetch(url, first_hop_ips=result.resolved_ips)

        result.final_url = fetched_page.final_url
        result.status_code = fetched_page.status_code

        for header, (finding_title, severity) in SECURITY_HEADERS.items():
            value = fetched_page.headers.get(header)
            result.security_headers[header] = value

            if not value:
                _add_finding(
                    result,
                    finding_title,
                    severity,
                    f"The response did not include the {header} header.",
                    "The browser may lack an additional security restriction.",
                    f"Configure the web server to send an appropriate {header} header.",
                )

        result.checks_completed.append("HTTP security header inspection")

        if fetched_page.body:
            _analyse_html(result, fetched_page.final_url, fetched_page.body)

            if fetched_page.body_truncated:
                result.limitations.append(
                    f"HTML response exceeded the {len(fetched_page.body)}-byte inspection limit; only the first portion was analysed."
                )
        else:
            result.limitations.append(f"No HTML body available. Content type: {fetched_page.content_type!r}.")

        if fetched_page.redirect_count:
            result.checks_completed.append("Redirect-chain inspection")

        result.limitations.append("Inspection is passive. JavaScript was not executed, and forms were not submitted.")

        status = AnalysisStatus.PARTIAL if result.limitations else AnalysisStatus.COMPLETED

        return AnalysisResult(module="M5", status=status, data=result, investigation_id=investigation_id)

    except NonPublicAddressError as error:
        result.error = str(error)
        return AnalysisResult(module="M5", status=AnalysisStatus.FAILED, data=result, investigation_id=investigation_id)

    except ResolutionError as error:
        result.error = str(error)
        return AnalysisResult(module="M5", status=AnalysisStatus.FAILED, data=result, investigation_id=investigation_id)

    except FetchError as error:
        result.error = error.message
        result.limitations.append(f"Fetch failed during {error.kind} inspection.")
        return AnalysisResult(module="M5", status=AnalysisStatus.PARTIAL, data=result, investigation_id=investigation_id)

    except (ValueError, TypeError) as error:
        result.error = str(error)
        return AnalysisResult(module="M5", status=AnalysisStatus.FAILED, data=result, investigation_id=investigation_id)
