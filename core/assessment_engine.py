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


