
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
        return [(None, result) for result in results]

    return [(None, results)]


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
    if not data:
        return

    for finding in getattr(data, "findings", []):
        output.findings.append(
            ReportFinding(
                title=finding.title,
                description=finding.evidence,
                severity=finding.severity,
                source_module="M1",
                impact=getattr(finding, "impact", ""),
                remediation=getattr(finding, "remediation", ""),
            )
        )

    for item in getattr(data, "evidence", []):
        output.evidence.append(item)


def _collect_m1(output, results):
    for _, result in _result_items(results):
        _collect_m1_single(output, result)


def _collect_m2(output, results):
    for reference, result in _result_items(results):
        data = _unwrap(result)
        if not data:
            continue

        for finding in getattr(data, "findings", []):
            output.findings.append(
                ReportFinding(
                    title=finding.title,
                    description=getattr(finding, "description", ""),
                    severity=finding.severity,
                    source_module="M2",
                    impact=getattr(finding, "impact", ""),
                    remediation=getattr(finding, "remediation", ""),
                )
            )

        for item in getattr(data, "evidence", []):
            output.evidence.append(item)


def _collect_m3(output, result):
    data = _unwrap(result)
    if not data:
        return

    for finding in getattr(data, "findings", []):
        output.findings.append(
            ReportFinding(
                title=finding.title,
                description=getattr(finding, "description", ""),
                severity=finding.severity,
                source_module="M3",
                impact=getattr(finding, "impact", ""),
                remediation=getattr(finding, "remediation", ""),
            )
        )

    for item in getattr(data, "evidence", []):
        output.evidence.append(item)


def _collect_m5_single(output, result):
    data = _unwrap(result)
    if not data:
        return

    for finding in getattr(data, "findings", []):
        output.findings.append(
            ReportFinding(
                title=finding.title,
                description=finding.evidence,
                severity=finding.severity,
                source_module="M5",
                impact=finding.impact,
                remediation=finding.remediation,
            )
        )

    for item in getattr(data, "checks_completed", []):
        output.evidence.append(
            ReportEvidence(
                source_module="M5",
                description=item,
            )
        )

    if getattr(data, "final_url", None):
        output.evidence.append(
            ReportEvidence(
                source_module="M5",
                description=f"Final inspected URL: {data.final_url}",
            )
        )

    for limitation in getattr(data, "limitations", []):
        output.evidence.append(
            ReportEvidence(
                source_module="M5",
                description=f"Limitation: {limitation}",
            )
        )

    if getattr(data, "error", None):
        output.evidence.append(
            ReportEvidence(
                source_module="M5",
                description=f"Inspection error: {data.error}",
            )
        )


def _collect_m5(output, results):
    for _, result in _result_items(results):
        _collect_m5_single(output, result)


def _collect_m4(output, result, investigation_id):
    data = _unwrap(result)
    if not data:
        return

    for finding in getattr(data, "findings", []):
        output.findings.append(
            ReportFinding(
                title=finding.title,
                description=getattr(finding, "description", ""),
                severity=finding.severity,
                source_module="M4",
                impact=getattr(finding, "impact", ""),
                remediation=getattr(finding, "remediation", ""),
            )
        )

    for item in getattr(data, "evidence", []):
        output.evidence.append(item)


def _deduplicate_indicators(indicators):
    grouped = {}

    for indicator in indicators:
        key = (indicator.indicator_type, indicator.value)

        if key not in grouped:
            grouped[key] = []

        if indicator.source_module not in grouped[key]:
            grouped[key].append(indicator.source_module)

    return [
        ReportIndicator(
            indicator_type=indicator_type,
            value=value,
            source_module=", ".join(sources),
        )
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

    shared_indicators = extract_indicators(
        investigation_id=investigation_id,
        original_url=original_url or "",
        m1_result=[result for _, result in _result_items(m1_result)],
        m3_result=m3_result,
        m5_result=[result for _, result in _result_items(m5_result)],
    )

    for shared in shared_indicators:
        for source in shared.sources:
            output.indicators.append(
                ReportIndicator(
                    indicator_type=shared.indicator_type.value,
                    value=shared.value,
                    source_module=source.module,
                )
            )

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

        elif finding.source_module == "M5":
            title = finding.title.lower()

            if title.startswith("missing ") and "header" in title:
                continue

            if "submit" in title and any(term in title for term in ("external", "different", "unrelated")):
                strong_count += 1
                score += 3.0
            elif "brand" in title and any(term in title for term in ("credential", "password", "sensitive")):
                score += 2.5
            elif "explicit phishing" in title or "social-engineering" in title or "social engineering" in title:
                score += 1.5
            elif any(term in title for term in ("sensitive form", "credential collection", "password form")):
                score += 2.0
            elif "password field" in title:
                score += 1.0
            elif any(term in title for term in ("suspicious account", "payment language", "account language")):
                score += 0.75
            elif "meta refresh" in title or "external iframe" in title:
                score += 0.25

    if any(f.source_module == "M2" for f in assessment.findings):
        score += 0.75

    if strong_count >= 2 or (strong_count >= 1 and score >= 5.0):
        return RiskLevel.HIGH

    if strong_count >= 1 or score >= 2.5:
        return RiskLevel.SUSPICIOUS

    statuses = assessment.module_statuses

    m1_statuses = [status for module, status in statuses.items() if module == "M1" or module.startswith("M1:")]
    m2_statuses = [status for module, status in statuses.items() if module.startswith("M2:")]
    m5_statuses = [status for module, status in statuses.items() if module == "M5" or module.startswith("M5:")]

    url_analysis_attempted = any(
        status not in ("not_applicable", "not_provided")
        for status in m1_statuses + m2_statuses + m5_statuses
    )

    m5_partial_has_evidence = any(f.source_module == "M5" for f in assessment.findings)

    m5_coverage_complete = (
        bool(m5_statuses)
        and all(
            status == "completed" or (status == "partial" and m5_partial_has_evidence)
            for status in m5_statuses
        )
    )

    url_coverage_complete = (
        bool(m1_statuses)
        and all(status == "completed" for status in m1_statuses)
        and m5_coverage_complete
        and all(status in ("completed", "skipped") for status in m2_statuses)
    )

    if assessment.investigation_type == "url":
        coverage_complete = url_coverage_complete
    elif assessment.investigation_type in ("message", "combined"):
        coverage_complete = (
            statuses.get("M3") == "completed"
            and (not url_analysis_attempted or url_coverage_complete)
        )
    else:
        coverage_complete = False

    return RiskLevel.LOW if coverage_complete else RiskLevel.INCONCLUSIVE


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

        severity_summary = ", ".join(
            f"{count} {severity}" for severity, count in sorted(severity_counts.items())
        )
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