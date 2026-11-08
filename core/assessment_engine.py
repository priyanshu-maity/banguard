
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from core.schema import ReportFinding, ReportIndicator, ReportEvidence


@dataclass
class AssessmentEvidence:
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)


