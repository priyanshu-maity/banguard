from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar


class AnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"

T = TypeVar("T")

@dataclass
class AnalysisResult(Generic[T]):
    investigation_id: str
    module: str
    status: AnalysisStatus
    data: T | None = None
    error: str | None = None
