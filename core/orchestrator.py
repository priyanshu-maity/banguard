
from dataclasses import dataclass, field
from uuid import uuid4
from urllib.parse import urlsplit

from core.schema import AnalysisResult, AnalysisStatus, ThreatReport
from core.assessment_engine import collect_assessment_evidence, create_threat_report, submit_and_verify_report
from engines.url_analyzer.url_analyzer import URLAnalyzer
from engines.tls_analyzer.tls_analyzer import TLSAnalyzer
from engines.website_security import analyze_website_security
from engines.message_analyzer.message_analyzer import MessageAnalyzer
from engines.threat_correlation.correlation_engine import correlate_investigation


@dataclass
class InvestigationResult:
    investigation_id: str
    original_url: str
    investigation_type: str = "url"
    message: str | None = None

    # Legacy single-result fields
    m1_result: AnalysisResult | None = None
    m5_result: AnalysisResult | None = None

    # Multi-URL results
    m1_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m2_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m5_results: dict[str, AnalysisResult] = field(default_factory=dict)

    # Message analysis
    m3_result: AnalysisResult | None = None

    # Unified results
    m4_result: AnalysisResult | None = None
    threat_report: ThreatReport | None = None
    report_submission: dict | None = None
    report_verification: dict | None = None
    report_submission_error: str | None = None


def _is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return parsed.scheme.lower() in ("http", "https") and bool(parsed.hostname)
    except (ValueError, AttributeError):
        return False


def _collect_urls(original_urls: list[str], m1_results: dict[str, AnalysisResult]) -> list[str]:
    """Collect original URLs and valid redirect destinations without duplicates."""
    candidates = list(original_urls)

    for result in m1_results.values():
        data = result.data

        if data is None:
            continue

        redirect_chain = getattr(data, "redirect_chain", None)

        if not isinstance(redirect_chain, tuple) or len(redirect_chain) < 2:
            continue

        for item in redirect_chain[1]:
            url = item.split(" -> ", 1)[-1].strip() if " -> " in item else item.strip()
            candidates.append(url)

    urls = []

    for url in candidates:
        if not isinstance(url, str) or not _is_valid_http_url(url):
            continue

        if url not in urls:
            urls.append(url)

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


def _run_message_analysis(message: str, investigation_id: str) -> AnalysisResult:
    """Run M3 while preserving extracted indicators if language analysis fails."""
    analyzer = MessageAnalyzer(message)

    try:
        data = analyzer.analyze()
        return AnalysisResult(investigation_id=investigation_id, module="M3", status=AnalysisStatus.COMPLETED, data=data)

    except Exception as error:
        data = analyzer.result

        if analyzer.sanitized_message is not None:
            return AnalysisResult(investigation_id=investigation_id, module="M3", status=AnalysisStatus.PARTIAL, data=data, error=str(error))

        return AnalysisResult(investigation_id=investigation_id, module="M3", status=AnalysisStatus.FAILED, data=data, error=str(error))


def _run_url_analysis(url: str, investigation_id: str, investigation: InvestigationResult):
    """Run M1, M2 and M5 for one URL and its redirect destinations."""
    try:
        analyzer = URLAnalyzer(url)
        data = analyzer.analyze()
        normalized_url = analyzer.normalized_url

        investigation.m1_results[url] = AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.COMPLETED, data=data)

        if investigation.m1_result is None:
            investigation.m1_result = investigation.m1_results[url]

        tls_urls = _collect_urls([normalized_url or url], {url: investigation.m1_results[url]})

        for target_url in tls_urls:
            if target_url not in investigation.m2_results:
                investigation.m2_results[target_url] = _run_tls_analysis(target_url, investigation_id)

    except Exception as error:
        investigation.m1_results[url] = AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.FAILED, error=str(error))

        if investigation.m1_result is None:
            investigation.m1_result = investigation.m1_results[url]

    analysis_url = normalized_url if "normalized_url" in locals() else url

    try:
        investigation.m5_results[url] = analyze_website_security(analysis_url, investigation_id)

    except Exception as error:
        investigation.m5_results[url] = AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED, error=str(error))

    if investigation.m5_result is None:
        investigation.m5_result = investigation.m5_results[url]


def run_investigation(url: str | None = None, investigation_id: str | None = None, investigation_type: str = "url", message: str | None = None, submit_to_blockchain: bool = True) -> InvestigationResult:
    """Run a URL, message, or combined investigation and generate one unified report."""

    if investigation_type not in ("url", "message", "combined"):
        raise ValueError("investigation_type must be 'url', 'message', or 'combined'.")

    if investigation_type == "url" and (not isinstance(url, str) or not url.strip()):
        raise ValueError("A URL must be provided for a URL investigation.")

    if investigation_type in ("message", "combined") and (not isinstance(message, str) or not message.strip()):
        raise ValueError("A message must be provided for a message or combined investigation.")

    if url is not None and not isinstance(url, str):
        raise TypeError("URL must be a string.")

    investigation_id = investigation_id or str(uuid4())
    original_url = url.strip() if isinstance(url, str) else ""

    investigation = InvestigationResult(
        investigation_id=investigation_id,
        original_url=original_url,
        investigation_type=investigation_type,
        message=message,
    )

    # M3: Analyze the message once and extract all indicators.
    if investigation_type in ("message", "combined"):
        investigation.m3_result = _run_message_analysis(message, investigation_id)

    # Collect URLs from the explicit URL input and M3 extraction.
    original_urls = []

    if original_url:
        original_urls.append(original_url)

    if investigation.m3_result and investigation.m3_result.data:
        for extracted_url in investigation.m3_result.data.urls:
            if extracted_url not in original_urls:
                original_urls.append(extracted_url)

    # M1, M2 and M5: Analyze every discovered URL.
    for target_url in original_urls:
        if _is_valid_http_url(target_url):
            _run_url_analysis(target_url, investigation_id, investigation)

    # M4: Correlate all indicators in one database operation.
    try:
        investigation.m4_result = correlate_investigation(
            investigation_id=investigation_id,
            original_url=original_url,
            m1_result=list(investigation.m1_results.values()),
            m2_result=None,
            m3_result=investigation.m3_result,
            m5_result=list(investigation.m5_results.values()),
        )

    except Exception as error:
        investigation.m4_result = AnalysisResult(investigation_id=investigation_id, module="M4", status=AnalysisStatus.FAILED, error=str(error))

    # Assessment: Generate one unified report.
    assessment = collect_assessment_evidence(
        investigation_id=investigation_id,
        original_url=original_url,
        m1_result=investigation.m1_results,
        m2_results=investigation.m2_results,
        m3_result=investigation.m3_result,
        m4_result=investigation.m4_result,
        m5_result=investigation.m5_results,
        investigation_type=investigation_type,
    )

    investigation.threat_report = create_threat_report(investigation_id, assessment)

    # M6: Submit and verify only when explicitly enabled.
    if submit_to_blockchain:
        try:
            m6_result = submit_and_verify_report(investigation.threat_report)
            investigation.report_submission = m6_result["submission"]
            investigation.report_verification = m6_result["verification"]

        except Exception as error:
            investigation.report_submission_error = str(error)

    return investigation
