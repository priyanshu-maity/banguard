from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from core.schema import RiskLevel, ReportFinding, ReportIndicator, ReportEvidence, ThreatReport
from engines.threat_correlation.indicator_extractor import extract_indicators


@dataclass
class AssessmentEvidence:
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)
    module_statuses: dict[str, str] = field(default_factory=dict)
    investigation_type: str = "url"


def _unwrap(result):
    return getattr(result, "data", None) if result is not None else None


def _result_items(results):
    """Normalize single, multiple, or URL-keyed module results."""
    if results is None:
        return []

    if isinstance(results, dict):
        return list(results.items())

    if isinstance(results, (list, tuple)):
        return [(str(index), result) for index, result in enumerate(results)]

    return [("", results)]


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


def _record_result_statuses(output, module, results):
    items = _result_items(results)

    if not items:
        _record_status(output, module, None)
        return

    for reference, result in items:
        _record_status(output, module, result, reference or None)


def _collect_m1_single(output, result):
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

    domain_exists = getattr(data, "domain_exists", None)

    if isinstance(domain_exists, tuple) and domain_exists and domain_exists[0] is False:
        _add_evidence(output, f"Domain resolution failed: {domain_exists[1]}", "M1")

    redirect_chain = getattr(data, "redirect_chain", None)

    if isinstance(redirect_chain, tuple) and redirect_chain and redirect_chain[0]:
        for redirect in redirect_chain[1]:
            _add_evidence(output, f"Redirect observed: {redirect}", "M1", redirect)


def _collect_m1(output, results):
    for _, result in _result_items(results):
        _collect_m1_single(output, result)


def _collect_m2(output, results):
    for url, result in _result_items(results):
        data = _unwrap(result)
        _record_status(output, "M2", result, url or None)

        if data is None:
            error = getattr(result, "error", None)

            if error:
                _add_evidence(output, f"TLS analysis error: {error}", "M2", url or None)

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

        https_available = getattr(data, "https_available", None)

        if isinstance(https_available, tuple) and https_available and https_available[0] is False:
            _add_evidence(output, f"TLS handshake was unavailable: {https_available[1]}", "M2", url or None)

        for field_name, title, severity, description in checks:
            value = getattr(data, field_name, None)

            if not isinstance(value, tuple) or not value or value[0] is not True:
                continue

            details = value[1] if len(value) > 1 else None
            description = f"{description} Details: {details}" if details else description
            description = f"{description} URL: {url}"

            _add_finding(output, title, description, severity, "M2")
            _add_evidence(output, description, "M2", url or None)


def _collect_m3(output, result):
    data = _unwrap(result)

    if data is None:
        return

    checks = [
        ("urgency", "Urgency language detected", "low", "The message contains urgency language."),
        ("fear_or_threat", "Fear or threat language detected", "medium", "The message contains fear or threat language."),
        ("authority_impersonation", "Authority impersonation indicator", "medium", "The message contains language claiming or implying authority."),
        ("financial_manipulation", "Financial manipulation indicator", "medium", "The message contains financial manipulation language."),
        ("credential_requests", "Credential request detected", "high", "The message requests credentials or sensitive account information."),
        ("reward_or_prize_lure", "Reward or prize lure detected", "medium", "The message contains a reward or prize lure."),
        ("secrecy_or_isolation", "Secrecy or isolation language detected", "medium", "The message encourages secrecy or discourages consultation."),
    ]

    for field_name, title, severity, description in checks:
        value = getattr(data, field_name, None)

        if not isinstance(value, tuple) or not value or value[0] is not True:
            continue

        snippets = value[1] if len(value) > 1 else []
        details = "; ".join(snippets) if snippets else "No exact evidence snippet was provided."
        description = f"{description} Evidence: {details}"

        _add_finding(output, title, description, severity, "M3")
        _add_evidence(output, description, "M3")

    if data.claimed_brand:
        _add_evidence(output, f"The message claims association with the brand: {data.claimed_brand}. This claim has not been independently verified.", "M3")


def _collect_m4(output, result, investigation_id):
    data = _unwrap(result)

    if data is None:
        return

    grouped = {}

    for relationship in data.relationships:
        historical_ids = {item for item in relationship.investigation_ids if item != investigation_id}

        for shared in relationship.shared_indicators:
            key = (shared.indicator_type.value, shared.value)

            if key not in grouped:
                grouped[key] = {"investigations": set(), "sources": set()}

            grouped[key]["investigations"].update(historical_ids)
            grouped[key]["sources"].update(source.module for source in shared.sources)

    for (indicator_type, value), details in grouped.items():
        if not details["investigations"]:
            continue

        investigations = ", ".join(sorted(details["investigations"]))
        sources = ", ".join(sorted(details["sources"]))

        description = (
            f"Historical correlation: shared {indicator_type} indicator {value}. "
            f"Previously observed in investigations: {investigations}. "
            f"Original indicator sources: {sources}. "
            "A shared indicator does not establish common ownership, coordination, or malicious activity."
        )

        _add_evidence(output, description, "M4")


def _collect_m5_single(output, result):
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


def _collect_m5(output, results):
    for _, result in _result_items(results):
        _collect_m5_single(output, result)


def _deduplicate_indicators(indicators):
    grouped = {}

    for indicator in indicators:
        key = (indicator.indicator_type, indicator.value)

        if key not in grouped:
            grouped[key] = []

        if indicator.source_module not in grouped[key]:
            grouped[key].append(indicator.source_module)

    return [
        ReportIndicator(indicator_type=indicator_type, value=value, source_module=", ".join(sources))
        for (indicator_type, value), sources in grouped.items()
    ]


def _record_url_module_statuses(output, m1_result, m5_result):
    """Record URL module statuses or mark them not applicable when no URLs were analyzed."""
    if _result_items(m1_result):
        _record_result_statuses(output, "M1", m1_result)
    else:
        output.module_statuses["M1"] = "not_applicable"

    if _result_items(m5_result):
        _record_result_statuses(output, "M5", m5_result)
    else:
        output.module_statuses["M5"] = "not_applicable"


def collect_assessment_evidence(investigation_id, original_url="", m1_result=None, m2_results=None, m3_result=None, m4_result=None, m5_result=None, investigation_type="url"):
    """Collect evidence according to the type of investigation."""

    if investigation_type not in ("url", "message", "combined"):
        raise ValueError("investigation_type must be 'url', 'message', or 'combined'.")

    output = AssessmentEvidence(investigation_type=investigation_type)

    if investigation_type == "url":
        _record_result_statuses(output, "M1", m1_result)
        output.module_statuses["M3"] = "not_applicable"
        _record_status(output, "M4", m4_result)
        _record_result_statuses(output, "M5", m5_result)

        _collect_m1(output, m1_result)
        _collect_m2(output, m2_results)
        _collect_m5(output, m5_result)

    elif investigation_type == "message":
        _record_url_module_statuses(output, m1_result, m5_result)
        _record_status(output, "M3", m3_result)
        _record_status(output, "M4", m4_result)

        _collect_m1(output, m1_result)
        _collect_m2(output, m2_results)
        _collect_m3(output, m3_result)
        _collect_m5(output, m5_result)

    else:
        _record_url_module_statuses(output, m1_result, m5_result)
        _record_status(output, "M3", m3_result)
        _record_status(output, "M4", m4_result)

        _collect_m1(output, m1_result)
        _collect_m2(output, m2_results)
        _collect_m3(output, m3_result)
        _collect_m5(output, m5_result)

    _collect_m4(output, m4_result, investigation_id)

    # Extract indicators from all available module results.
    shared_indicators = extract_indicators(
        investigation_id=investigation_id,
        original_url=original_url or "",
        m1_result=[result for _, result in _result_items(m1_result)],
        m2_result=None,
        m3_result=m3_result,
        m5_result=[result for _, result in _result_items(m5_result)],
    )

    for shared in shared_indicators:
        for source in shared.sources:
            output.indicators.append(ReportIndicator(indicator_type=shared.indicator_type.value, value=shared.value, source_module=source.module))

    output.indicators = _deduplicate_indicators(output.indicators)
    return output


def classify_risk(assessment: AssessmentEvidence) -> RiskLevel:
    """Classify investigation risk using conservative, evidence-based rules."""

    strong_m1 = {
        "Potential typosquatting detected",
        "Mixed Unicode scripts detected",
        "Brand name found in subdomain",
        "Unsafe redirect destination detected",
    }

    moderate_m1 = {
        "Punycode detected",
        "Suspicious keywords in URL",
        "Cross-domain redirect detected",
        "URL shortener detected",
        "Newly registered domain",
        "Impersonating domain has no MX record",
    }

    strong_count = 0
    score = 0.0

    for finding in assessment.findings:
        if finding.source_module == "M1":
            if finding.title in strong_m1:
                strong_count += 1
                score += 3.0
            elif finding.title in moderate_m1:
                score += 1.5
            else:
                score += 0.5

        elif finding.source_module == "M3":
            if finding.title == "Credential request detected":
                score += 2.5
            elif finding.title in {
                "Fear or threat language detected",
                "Authority impersonation indicator",
                "Financial manipulation indicator",
                "Secrecy or isolation language detected",
                "Reward or prize lure detected",
            }:
                score += 1.0
            elif finding.title == "Urgency language detected":
                score += 0.25

    # TLS issues are security concerns, but do not independently establish maliciousness.
    if any(f.source_module == "M2" for f in assessment.findings):
        score += 0.75

    # Website security findings have limited weight.
    if any(f.source_module == "M5" for f in assessment.findings):
        score += 0.5

    # Strong findings can independently elevate risk despite incomplete coverage.
    if strong_count >= 2 or (strong_count >= 1 and score >= 5.0):
        return RiskLevel.HIGH

    if strong_count >= 1 or score >= 2.5:
        return RiskLevel.SUSPICIOUS

    statuses = assessment.module_statuses

    m1_statuses = [status for module, status in statuses.items() if module == "M1" or module.startswith("M1:")]
    m2_statuses = [status for module, status in statuses.items() if module.startswith("M2:")]
    m5_statuses = [status for module, status in statuses.items() if module == "M5" or module.startswith("M5:")]

    url_analysis_attempted = any(
        status not in ("not_applicable", "not_provided") for status in m1_statuses + m2_statuses + m5_statuses)
    url_coverage_complete = (
        bool(m1_statuses)
        and bool(m5_statuses)
        and all(status == "completed" for status in m1_statuses)
        and all(status == "completed" for status in m5_statuses)
        and all(status in ("completed", "skipped") for status in m2_statuses)
    )

    if assessment.investigation_type == "url":
        coverage_complete = url_coverage_complete

    elif assessment.investigation_type == "message":
        coverage_complete = statuses.get("M3") == "completed" and (not url_analysis_attempted or url_coverage_complete)

    elif assessment.investigation_type == "combined":
        coverage_complete = statuses.get("M3") == "completed" and (not url_analysis_attempted or url_coverage_complete)

    else:
        coverage_complete = False

    if not coverage_complete:
        return RiskLevel.INCONCLUSIVE

    return RiskLevel.LOW


def create_threat_report(investigation_id: str, assessment: AssessmentEvidence) -> ThreatReport:
    """Generate a unified ThreatReport from collected assessment evidence."""

    risk_level = classify_risk(assessment)
    finding_count = len(assessment.findings)
    indicator_count = len(assessment.indicators)

    summaries = {
        RiskLevel.LOW: "The completed analysis identified no significant suspicious activity.",
        RiskLevel.SUSPICIOUS: "Suspicious indicators were identified. Further investigation is recommended.",
        RiskLevel.HIGH: "Multiple strong indicators of potentially malicious activity were identified.",
        RiskLevel.CONFIRMED_MALICIOUS: "Authoritative threat intelligence confirmed malicious activity.",
        RiskLevel.INCONCLUSIVE: "Available analysis was insufficient to reach a reliable security assessment.",
    }

    summary = summaries[risk_level]

    if finding_count:
        summary += f" The analysis recorded {finding_count} finding{'s' if finding_count != 1 else ''}."

        severity_counts = {}

        for finding in assessment.findings:
            severity = str(finding.severity).lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        severity_summary = ", ".join(f"{count} {severity}" for severity, count in sorted(severity_counts.items()))
        summary += f" Severity breakdown: {severity_summary}."
    else:
        summary += " No findings were recorded."

    if indicator_count:
        summary += f" {indicator_count} unique threat indicator{'s' if indicator_count != 1 else ''} were recorded."

    incomplete = [
        f"{module}: {status}"
        for module, status in assessment.module_statuses.items()
        if status in ("partial", "failed")
    ]

    if incomplete:
        summary += " Incomplete analyses: " + ", ".join(incomplete) + "."

    return ThreatReport(
        report_id=str(uuid4()),
        investigation_id=investigation_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        risk_level=risk_level,
        summary=summary,
        findings=list(assessment.findings),
        indicators=list(assessment.indicators),
        evidence=list(assessment.evidence),
    )


def submit_and_verify_report(report):
    """Submit a generated ThreatReport to M6 and verify its integrity."""
    from engines.threat_intelligence.report_manager import submit_report
    from engines.threat_intelligence.verification import verify_report

    submission = submit_report(report)
    verification = verify_report(report.report_id, submission["version"])

    return {
        "submission": submission,
        "verification": verification,
    }
