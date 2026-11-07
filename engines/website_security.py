from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit

from core.schemas import AnalysisResult, AnalysisStatus
from core.network_safety import (
    NonPublicAddressError,
    ResolutionError,
    normalise_hostname,
    resolve_public_ips,
)
from core.fetch_redirect_chain import FetchError, safe_fetch


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SecurityFinding:
    title: str
    severity: Severity
    evidence: str
    impact: str
    remediation: str


@dataclass
class WebsiteSecurityResult:
    publicly_resolvable: bool | None = None
    resolved_ips: list[str] = field(default_factory=list)

    final_url: str | None = None
    status_code: int | None = None

    security_headers: dict[str, bool | None] = field(default_factory=dict)
    findings: list[SecurityFinding] = field(default_factory=list)
    checks_completed: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    error: str | None = None
