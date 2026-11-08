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

def _run_tls_analysis(url: str, investigation_id: str) -> AnalysisResult:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "https":
            return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.SKIPPED, error="TLS analysis is not applicable to HTTP URLs.")

        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            raise ValueError("URL does not contain a valid hostname.")
        tls_data = TLSAnalyzer(host, port).analyze()

        return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.COMPLETED, data=tls_data)
    except Exception as error:
        return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.FAILED, error=str(error))

def run_investigation(url: str, investigation_id: str | None = None) -> InvestigationResult:
    if not url or not url.strip():
        raise ValueError("A URL must be provided.")

    investigation_id = investigation_id or str(uuid4())
    investigation = InvestigationResult(investigation_id=investigation_id, original_url=url)

    url_analyzer = None
    normalized_url = None
    m1_data = None

    # M1: URL analysis
    try:
        url_analyzer = URLAnalyzer(url)
        m1_data = url_analyzer.analyze()
        normalized_url = url_analyzer.normalized_url
        investigation.m1_result = AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.COMPLETED, data=m1_data)
    except Exception as error:
        investigation.m1_result = AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.FAILED, error=str(error))

    analysis_url = normalized_url or url

    # M2: TLS analysis for the original URL and every redirect
    urls = _collect_urls(url, m1_data, normalized_url)
    for target_url in urls:
        investigation.m2_results[target_url] = _run_tls_analysis(target_url, investigation_id)

    # M5: Website security analysis
    try:
        investigation.m5_result = analyze_website_security(analysis_url, investigation_id)
    except Exception as error:
        investigation.m5_result = AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED, error=str(error))

    # M4: Threat correlation
    try:
        investigation.m4_result = correlate_investigation(
            investigation_id=investigation_id,
            original_url=analysis_url,
            m1_result=investigation.m1_result,
            m2_result=None,
            m3_result=None,
            m5_result=investigation.m5_result
        )
    except Exception as error:
        investigation.m4_result = AnalysisResult(investigation_id=investigation_id, module="M4", status=AnalysisStatus.FAILED, error=str(error))

    return investigation

