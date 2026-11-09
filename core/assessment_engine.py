import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from core.schema import RiskLevel, ReportFinding, ReportIndicator, ReportEvidence, ThreatReport
from engines.threat_correlation.indicator_extractor import extract_indicators
from core.risk_model import ActiveSignal, RiskModel, RiskModelConfig, RiskScore
from core.signal_catalog import (
    INTERACTIONS, M1_SIGNALS, M2_SIGNALS, M3_SIGNALS, M5_SIGNALS, SignalSpec, severity_from_lr,
)
from core.signal_reader import format_detail, read_signals

logger = logging.getLogger(__name__)

MODEL = RiskModel(RiskModelConfig())
CONFIRMED_VT_MIN_ENGINES = 3  # malicious detections needed to call a URL Confirmed Malicious
MIN_COVERAGE = 0.60  # below this, a low-risk result is reported as Inconclusive

_SPECS = {(s.module, s.name): s for s in M1_SIGNALS + M2_SIGNALS + M3_SIGNALS + M5_SIGNALS}
_M4_LR_BY_SEVERITY = {"high": 4.0, "medium": 2.5, "low": 1.3}


@dataclass
class AssessmentEvidence:
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)
    module_statuses: dict[str, str] = field(default_factory=dict)
    investigation_type: str = "url"
    risk_level: RiskLevel | None = None
    risk_score: RiskScore | None = None
    coverage: float = 0.0
    authoritative_evidence: list[str] = field(default_factory=list)


# Result helpers
def _unwrap(result):
    return getattr(result, "data", None) if result is not None else None


def _result_items(results):
    """Normalise single, multiple, or reference-keyed module results into (reference, result) pairs."""
    if results is None:
        return []
    if isinstance(results, dict):
        return list(results.items())
    if isinstance(results, (list, tuple)):
        return [(None, result) for result in results]
    return [(None, results)]


def _status_of(result) -> str:
    if result is None:
        return "not_provided"
    value = getattr(result, "status", None)
    return getattr(value, "value", str(value)) if value is not None else "unknown"


def _record_result_statuses(output, module, results, not_applicable_if_empty=False):
    items = _result_items(results)
    if not items:
        output.module_statuses[module] = "not_applicable" if not_applicable_if_empty else "not_provided"
        return
    for reference, result in items:
        key = f"{module}:{reference}" if reference else module
        output.module_statuses[key] = _status_of(result)


def _severity_text(severity) -> str:
    return str(getattr(severity, "value", severity)).lower()


# Collection: signals -> findings
def _gather_signals(m1_result, m2_results, m3_result, m4_result, m5_result) -> list[ActiveSignal]:
    signals: list[ActiveSignal] = []
    for reference, result in _result_items(m1_result):
        signals += read_signals(_unwrap(result), M1_SIGNALS, reference or "url")
    for reference, result in _result_items(m5_result):
        signals += read_signals(_unwrap(result), M5_SIGNALS, reference or "url")  # same scope key as M1
    for _, result in _result_items(m2_results):
        signals += read_signals(_unwrap(result), M2_SIGNALS, "global")
    signals += read_signals(_unwrap(m3_result), M3_SIGNALS, "message")
    return signals


def _finding_from_signal(signal: ActiveSignal) -> ReportFinding:
    spec: SignalSpec = _SPECS[(signal.module, signal.name)]
    return ReportFinding(
        title=spec.title,
        description=spec.evidence.format(detail=format_detail(signal.detail)),
        severity=spec.severity or severity_from_lr(signal.lr),
        source_module=signal.module,
        impact=spec.impact,
        remediation=spec.remediation,
    )


def _collect_m4(output, result, signals):
    """Correlation findings are passed through, and also scored as one evidence group."""
    data = _unwrap(result)
    if not data:
        return
    for finding in getattr(data, "findings", []):
        severity = _severity_text(getattr(finding, "severity", "low"))
        output.findings.append(ReportFinding(
            title=finding.title,
            description=getattr(finding, "description", ""),
            severity=severity,
            source_module="M4",
            impact=getattr(finding, "impact", ""),
            remediation=getattr(finding, "remediation", ""),
        ))
        signals.append(ActiveSignal(f"m4:{finding.title}", "M4", "campaign_correlation",
                                    _M4_LR_BY_SEVERITY.get(severity, 1.3), None, "global"))
    for item in getattr(data, "evidence", []):
        output.evidence.append(item)


def _authoritative_evidence(m1_result) -> list[str]:
    """Evidence strong enough to call a URL Confirmed Malicious without the model."""
    found = []
    for reference, result in _result_items(m1_result):
        data = _unwrap(result)
        flag, count = (getattr(data, "virustotal_malicious", None) or (None, None))[:2] if data else (None, None)
        if flag is True and isinstance(count, int) and count >= CONFIRMED_VT_MIN_ENGINES:
            found.append(f"{reference or 'URL'}: flagged malicious by {count} VirusTotal engines")
    return found


# Evidence coverage
def _flag_of(value):
    return value[0] if isinstance(value, tuple) and value else value if isinstance(value, bool) else None


def _coverage(m1_result, m2_results, m3_result, m5_result, investigation_type) -> float:
    """Weighted share of the expected checks that produced a usable result (0 to 1)."""
    checks: list[tuple[float, float]] = []  # (weight, score)

    def completion(result) -> float:
        status = _status_of(result)
        return 1.0 if status == "completed" else 0.5 if status == "partial" else 0.0

    m1_items = _result_items(m1_result)
    if m1_items:
        m5_by_ref = dict(_result_items(m5_result))
        structure, age, intel, page = [], [], [], []
        for reference, result in m1_items:
            data = _unwrap(result)
            structure.append(completion(result))
            age.append(1.0 if data is not None and (getattr(data, "newly_registered_domain", (None,)) or (None,))[0] is not None else 0.0)
            providers = getattr(data, "threat_intelligence_provider_status", {}) if data is not None else {}
            intel.append(1.0 if any(v in ("success", "no_report") for v in providers.values()) else 0.0)
            page.append(completion(m5_by_ref.get(reference)))
        mean = lambda values: sum(values) / len(values)
        checks += [(3.0, mean(structure)), (2.0, mean(age)), (3.0, mean(intel)), (0.5, mean(page))]

        tls = [result for _, result in _result_items(m2_results) if _status_of(result) != "skipped"]
        if tls:
            checks.append((1.5, sum(completion(r) for r in tls) / len(tls)))

    if investigation_type in ("message", "combined"):
        # A message counts as covered only to the extent its language checks were actually evaluated.
        data = _unwrap(m3_result)
        names = [spec.name for spec in M3_SIGNALS if spec.name != "brand_impersonation"]
        evaluated = [_flag_of(getattr(data, name, None)) is not None for name in names] if data is not None else []
        fraction = sum(evaluated) / len(evaluated) if evaluated else 0.0
        checks.append((3.0, completion(m3_result) * fraction))

    total = sum(weight for weight, _ in checks)
    return sum(weight * score for weight, score in checks) / total if total else 0.0


# Public API
def collect_assessment_evidence(investigation_id, original_url="", m1_result=None, m2_results=None, m3_result=None,
                                m4_result=None, m5_result=None, investigation_type="url") -> AssessmentEvidence:
    """Turn module signals into findings, evidence, a risk score and a risk level."""
    if investigation_type not in ("url", "message", "combined"):
        raise ValueError("investigation_type must be 'url', 'message', or 'combined'.")

    output = AssessmentEvidence(investigation_type=investigation_type)

    # Statuses
    url_expected = investigation_type == "url"
    _record_result_statuses(output, "M1", m1_result, not_applicable_if_empty=not url_expected)
    _record_result_statuses(output, "M2", m2_results, not_applicable_if_empty=True)
    _record_result_statuses(output, "M5", m5_result, not_applicable_if_empty=not url_expected)
    if investigation_type == "url":
        output.module_statuses["M3"] = "not_applicable"
    else:
        output.module_statuses["M3"] = _status_of(m3_result)
    output.module_statuses["M4"] = _status_of(m4_result)

    # Signals, findings, scoring
    signals = _gather_signals(m1_result, m2_results, m3_result, m4_result, m5_result)
    for signal in signals:
        output.findings.append(_finding_from_signal(signal))
    _collect_m4(output, m4_result, signals)

    score = MODEL.score(signals, INTERACTIONS)
    output.risk_score = score
    for fired in score.interactions:
        output.findings.append(ReportFinding(
            title=fired.title,
            description=f"{fired.description} Signals involved: {', '.join(fired.members)}.",
            severity="high",
            source_module="ASSESSMENT",
            impact="Combinations of indicators are much stronger evidence than any one of them alone.",
            remediation="Do not interact with the link or message until it has been verified through an official channel.",
        ))

    output.authoritative_evidence = _authoritative_evidence(m1_result)
    output.coverage = _coverage(m1_result, m2_results, m3_result, m5_result, investigation_type)
    output.risk_level = _decide_level(score, output)
    _add_evidence(output, score, m1_result, m5_result)
    output.indicators = _collect_indicators(output, investigation_id, original_url, m1_result, m3_result, m5_result)
    return output


def _decide_level(score: RiskScore, output: AssessmentEvidence) -> RiskLevel:
    if output.authoritative_evidence:
        return RiskLevel.CONFIRMED_MALICIOUS
    label = MODEL.level_label(score.probability)
    if label == "high":
        return RiskLevel.HIGH
    if label == "suspicious":
        return RiskLevel.SUSPICIOUS
    # Nothing alarming was found, but only say Low if enough of the checks actually ran.
    return RiskLevel.LOW if output.coverage >= MIN_COVERAGE else RiskLevel.INCONCLUSIVE


def classify_risk(assessment: AssessmentEvidence) -> RiskLevel:
    return assessment.risk_level or RiskLevel.INCONCLUSIVE


def _add_evidence(output, score: RiskScore, m1_result, m5_result) -> None:
    def add(module, description):
        output.evidence.append(ReportEvidence(source_module=module, description=description))

    for reference, result in _result_items(m1_result):
        data = _unwrap(result)
        if not data:
            continue
        chain = getattr(data, "redirect_chain", None)
        if isinstance(chain, tuple) and len(chain) > 1 and chain[0] and chain[1]:
            add("M1", f"Redirect chain for {reference or 'URL'}: {' | '.join(str(x) for x in chain[1])}")
        providers = getattr(data, "threat_intelligence_provider_status", None)
        if providers:
            add("M1", "Threat-intelligence provider status: " + ", ".join(f"{k}={v}" for k, v in providers.items()))

    for reference, result in _result_items(m5_result):
        data = _unwrap(result)
        fetched = getattr(data, "page_fetched", None) if data else None
        if fetched and fetched[0] and fetched[1]:
            add("M5", f"Final inspected URL: {fetched[1]}")

    for line in output.authoritative_evidence:
        add("ASSESSMENT", f"Authoritative evidence: {line}")

    # Explainability: show how the score was built
    parts = [f"{group} x{lr:.1f}" for group, lr in sorted(score.group_lr.items(), key=lambda kv: -kv[1])]
    parts += [f"{f.title} x{f.lr:.1f}" for f in score.interactions]
    add("ASSESSMENT", f"Risk model: prior {score.prior:.0%}, score {score.probability:.2f}. Contributions: "
                      f"{'; '.join(parts) if parts else 'none'}.")
    if score.capped:
        add("ASSESSMENT", score.cap_reason or "Score capped.")
    add("ASSESSMENT", f"Evidence coverage: {output.coverage:.0%} of expected checks produced a usable result.")


def _collect_indicators(output, investigation_id, original_url, m1_result, m3_result, m5_result) -> list[ReportIndicator]:
    try:
        shared = extract_indicators(
            investigation_id=investigation_id,
            original_url=original_url or "",
            m1_result=[r for _, r in _result_items(m1_result)],
            m3_result=m3_result,
            m5_result=[r for _, r in _result_items(m5_result)],
        )
    except Exception:  # a broken extractor must not sink the whole report
        logger.exception("Indicator extraction failed for %s", investigation_id)
        output.evidence.append(ReportEvidence(source_module="ASSESSMENT", description="Indicator extraction did not complete."))
        return []

    indicators = [
        ReportIndicator(indicator_type=item.indicator_type.value, value=item.value, source_module=source.module)
        for item in shared for source in item.sources
    ]
    grouped: dict[tuple, list[str]] = {}
    for indicator in indicators:
        sources = grouped.setdefault((indicator.indicator_type, indicator.value), [])
        if indicator.source_module not in sources:
            sources.append(indicator.source_module)
    return [ReportIndicator(indicator_type=t, value=v, source_module=", ".join(s)) for (t, v), s in grouped.items()]


def create_threat_report(investigation_id: str, assessment: AssessmentEvidence) -> ThreatReport:
    """Generate a unified ThreatReport from collected assessment evidence."""
    risk_level = classify_risk(assessment)
    score = assessment.risk_score

    summaries = {
        RiskLevel.LOW: "No significant malicious indicators were identified within the available checks. This is not a guarantee of safety.",
        RiskLevel.SUSPICIOUS: "Suspicious indicators were identified. Further investigation is recommended.",
        RiskLevel.HIGH: "Multiple strong indicators of potentially malicious activity were identified.",
        RiskLevel.CONFIRMED_MALICIOUS: "Authoritative threat intelligence confirmed malicious activity.",
        RiskLevel.INCONCLUSIVE: "Available analysis was insufficient to reach a reliable security assessment.",
    }
    summary = summaries[risk_level]

    if assessment.findings:
        count = len(assessment.findings)
        summary += f" The analysis recorded {count} finding{'s' if count != 1 else ''}."
        severity_counts: dict[str, int] = {}
        for finding in assessment.findings:
            severity = _severity_text(finding.severity)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        summary += " Severity breakdown: " + ", ".join(f"{n} {s}" for s, n in sorted(severity_counts.items())) + "."
    else:
        summary += " No findings were recorded."

    if assessment.indicators:
        n = len(assessment.indicators)
        summary += f" {n} unique threat indicator{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} recorded."

    if score is not None:
        summary += f" Risk model score: {score.probability:.2f} (uncalibrated), evidence coverage: {assessment.coverage:.0%}."
        if score.interactions:
            summary += " Key combinations: " + "; ".join(f.title for f in score.interactions) + "."

    incomplete = [f"{m}: {s}" for m, s in assessment.module_statuses.items() if s in ("partial", "failed")]
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
    return {"submission": submission, "verification": verification}