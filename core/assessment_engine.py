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

def _collect_m2(output, results):
    for url, result in (results or {}).items():
        data = _unwrap(result)
        _record_status(output, "M2", result, url)

        if data is None:
            if result is not None and result.error:
                _add_evidence(output, f"TLS analysis error: {result.error}", "M2", url)
            continue

        checks = [
            ("verification_failed", "Certificate verification failed", "high", "Certificate-chain verification failed."),
            ("certificate_expired", "Expired TLS certificate", "high", "The retrieved leaf certificate has expired."),
            ("certificate_not_yet_valid", "TLS certificate not yet valid", "high", "The retrieved leaf certificate is not yet valid."),
            ("hostname_mismatch", "TLS hostname mismatch", "high", "The certificate does not match the requested hostname."),
            ("self_signed", "Self-signed TLS certificate", "high", "The retrieved certificate is self-signed."),
            ("unknown_issuer", "Untrusted certificate issuer", "medium", "The certificate chain does not lead to a trusted root."),
            ("distrusted_ca_match", "Distrusted certificate authority match", "high", "The certificate matches a locally distrusted CA entry."),
        ]

        https_available = data.https_available

        if https_available[0] is False:
            _add_evidence(output, f"TLS handshake was unavailable: {https_available[1]}", "M2", url)

        for field_name, title, severity, description in checks:
            value = getattr(data, field_name, None)
            if not isinstance(value, tuple) or not value or value[0] is not True:
                continue

            details = value[1] if len(value) > 1 else None
            description = f"{description} Details: {details}" if details else description
            description = f"{description} URL: {url}"

            _add_finding(output, title, description, severity, "M2")
            _add_evidence(output, description, "M2", url)

def _collect_m4(output, result):
    data = _unwrap(result)
    if data is None:
        return

    for relationship in data.relationships:
        investigation_ids = ", ".join(relationship.investigation_ids)

        for shared in relationship.shared_indicators:
            indicator_sources = ", ".join(source.module for source in shared.sources)
            description = (
                f"Shared {shared.indicator_type.value} indicator: {shared.value}. "
                f"Related investigations: {investigation_ids}. "
                f"Original indicator sources: {indicator_sources}."
            )
            _add_evidence(output, description, "M4")

def _collect_m5(output, result):
    data = _unwrap(result)
    if data is None:
        return

    for finding in data.findings:
        severity = getattr(finding.severity, "value", str(finding.severity))
        _add_finding(output, finding.title, finding.evidence, severity, "M5", finding.impact, finding.remediation)
        _add_evidence(output, finding.evidence, "M5", data.final_url)

    for limitation in data.limitations:
        _add_evidence(output, f"Analysis limitation: {limitation}", "M5")

    if data.error:
        _add_evidence(output, f"Website security analysis error: {data.error}", "M5")

def collect_assessment_evidence(investigation_id, original_url, m1_result=None, m2_results=None, m3_result=None, m4_result=None, m5_result=None):
    """Collect module findings and reuse M4 for all indicator extraction."""

    output = AssessmentEvidence()
    _record_status(output, "M1", m1_result)
    _record_status(output, "M3", m3_result)
    _record_status(output, "M4", m4_result)
    _record_status(output, "M5", m5_result)

    for url, result in (m2_results or {}).items():
        _record_status(output, "M2", result, url)

    _collect_m1(output, m1_result)
    _collect_m2(output, m2_results)
    _collect_m4(output, m4_result)
    _collect_m5(output, m5_result)

    shared_indicators = extract_indicators(investigation_id=investigation_id, original_url=original_url, m1_result=m1_result, m2_result=None, m3_result=m3_result, m5_result=m5_result,)

    for shared in shared_indicators:
        for source in shared.sources:
            output.indicators.append(ReportIndicator(indicator_type=shared.indicator_type.value, value=shared.value, source_module=source.module,))

    return output
