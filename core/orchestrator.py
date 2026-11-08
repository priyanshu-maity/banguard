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

def _collect_urls(original_url: str, m1_data, normalized_url: str | None) -> list[str]:
    urls = []
    candidates = [normalized_url or original_url]

    if m1_data is not None:
        redirect_chain = m1_data.redirect_chain[1]
        for item in redirect_chain:
            url = item.split(" -> ", 1)[-1].strip()
            candidates.append(url)

    for url in candidates:
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                continue
            if url not in urls:
                urls.append(url)
        except ValueError:
            continue

    return urls
