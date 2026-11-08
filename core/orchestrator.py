from dataclasses import dataclass, field
from uuid import uuid4
from urllib.parse import urlsplit

from core.schema import AnalysisResult, AnalysisStatus
from engines.url_analyzer.url_analyzer import URLAnalyzer
from engines.tls_analyzer.tls_analyzer import TLSAnalyzer
from engines.website_security import analyze_website_security
from engines.threat_correlation.correlation_engine import correlate_investigation


@dataclass
class InvestigationResult:
    investigation_id: str
    original_url: str
    m1_result: AnalysisResult | None = None
    m2_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m4_result: AnalysisResult | None = None
    m5_result: AnalysisResult | None = None


