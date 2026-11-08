from dataclasses import dataclass, field

from core.schema import ReportFinding, ReportIndicator, ReportEvidence
from engines.threat_correlation.indicator_extractor import extract_indicators


@dataclass
class AssessmentEvidence:
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)
    module_statuses: dict[str, str] = field(default_factory=dict)


def _unwrap(result):
    return getattr(result, "data", None) if result is not None else None

def _add_finding(output, title, description, severity, module, impact=None, remediation=None):
    key = (title, description, module)
    if any((item.title, item.description, item.source_module) == key for item in output.findings):
        return
    output.findings.append(ReportFinding(title=title, description=description, severity=severity, source_module=module, impact=impact, remediation=remediation))


def _add_evidence(output, description, module, reference=None):
    key = (description, module, reference)
    if any((item.description, item.source_module, item.reference) == key for item in output.evidence):
        return
    output.evidence.append(ReportEvidence(description=description, source_module=module, reference=reference))

def _record_status(output, module, result, reference=None):
    if result is None:
        status = "not_provided"
    else:
        value = getattr(result, "status", None)
        status = getattr(value, "value", str(value)) if value is not None else "unknown"

    key = f"{module}:{reference}" if reference else module
    output.module_statuses[key] = status

def _collect_m1(output, result):
    data = _unwrap(result)
    if data is None:
        return

    checks = [
        ("has_userinfo", "Credentials embedded in URL", "high", "The URL contains embedded user information."),
        ("uses_ip_address", "IP address used as URL hostname", "medium", "The URL uses an IP address instead of a domain name."),
        ("excessive_hyphens", "Excessive hyphens in domain", "low", "The domain contains an unusually high number of hyphens."),
        ("excessive_subdomains", "Excessive subdomains", "low", "The domain contains an unusually high number of subdomains."),
        ("typosquatting_detected", "Potential typosquatting detected", "high", "The domain resembles a known brand."),
        ("uses_punycode", "Punycode detected", "medium", "The domain contains Punycode-encoded components."),
        ("mixed_unicode_scripts", "Mixed Unicode scripts detected", "high", "The domain combines characters from different writing systems."),
        ("brand_in_subdomain", "Brand name found in subdomain", "high", "A protected brand name appears in a subdomain."),
        ("suspicious_keywords", "Suspicious keywords in URL", "low", "The URL contains keywords commonly associated with suspicious links."),
        ("newly_registered_domain", "Newly registered domain", "medium", "The domain is less than 30 days old."),
        ("missing_a_record", "Missing A record", "low", "The domain does not have the expected A record."),
        ("missing_mx_on_impersonating_domain", "Impersonating domain has no MX record", "medium", "A brand-impersonating domain lacks an MX record."),
        ("cross_domain_redirect", "Cross-domain redirect detected", "medium", "The URL redirects to a different registered domain."),
        ("url_shortener_detected", "URL shortener detected", "medium", "A known URL-shortening service appears in the redirect chain."),
        ("ssrf_attempt_detected", "Unsafe redirect destination detected", "high", "A redirect destination resolved to a non-public address."),
    ]

    for field_name, title, severity, description in checks:
        value = getattr(data, field_name, None)
        if not isinstance(value, tuple) or not value or value[0] is not True:
            continue

        details = value[1] if len(value) > 1 else None
        description = f"{description} Details: {details}" if details else description

        _add_finding(output, title, description, severity, "M1")
        _add_evidence(output, description, "M1")

    if data.domain_exists[0] is False:
        _add_evidence(output, f"Domain resolution failed: {data.domain_exists[1]}", "M1")

    if data.redirect_chain[0]:
        for redirect in data.redirect_chain[1]:
            _add_evidence(output, f"Redirect observed: {redirect}", "M1", redirect)
