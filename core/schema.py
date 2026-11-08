
from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, TypeVar


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


T = TypeVar("T")


@dataclass
class AnalysisResult(Generic[T]):
    investigation_id: str
    module: str
    status: AnalysisStatus
    data: T | None = None
    error: str | None = None


@dataclass
class ReportFinding:
    title: str
    description: str
    severity: str
    source_module: str
    impact: str | None = None
    remediation: str | None = None


@dataclass
class ReportIndicator:
    indicator_type: str
    value: str
    source_module: str


@dataclass
class ReportEvidence:
    description: str
    source_module: str
    reference: str | None = None


@dataclass
class ThreatReport:
    report_id: str
    investigation_id: str
    created_at: str
    risk_level: RiskLevel
    summary: str
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)
