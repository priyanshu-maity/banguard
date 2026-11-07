from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    module: str
    title: str
    severity: Severity
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    recommendation: str


class AnalysisResult(BaseModel):
    investigation_id: str
    module: str
    status: AnalysisStatus
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
