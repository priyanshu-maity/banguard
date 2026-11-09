import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import uuid4

from core.schema import AnalysisResult, AnalysisStatus, RiskLevel, ThreatReport
from core.assessment_engine import collect_assessment_evidence, create_threat_report, submit_and_verify_report
from engines.url_analyzer.url_analyzer import URLAnalyzer
from engines.tls_analyzer.tls_analyzer import TLSAnalyzer
from engines.website_security.website_security import analyze_website_security
from engines.message_analyzer.message_analyzer import MessageAnalyzer
from engines.threat_correlation.correlation_engine import correlate_investigation

logger = logging.getLogger(__name__)

MAX_URLS = 5  # every URL triggers outbound DNS, HTTP and TLS traffic: this is an abuse limit
MAX_WORKERS = 4
PHASE_TIMEOUT_SECONDS = 90  # per phase; unfinished work is reported as failed
MAX_MESSAGE_CHARS = 10_000
MAX_URL_CHARS = 2048
TLS_ALLOWED_PORTS = (443, 8443)  # otherwise TLS errors reveal which ports are open on third-party hosts
# Reports at these levels are registered on the blockchain automatically. Low Risk reports are not.
SUBMIT_RISK_LEVELS = (RiskLevel.SUSPICIOUS, RiskLevel.HIGH, RiskLevel.CONFIRMED_MALICIOUS, RiskLevel.INCONCLUSIVE)

_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,64}")
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f\\]")


@dataclass
class InvestigationResult:
    investigation_id: str
    original_url: str
    investigation_type: str = "url"
    message: str | None = None

    # Legacy single-result fields
    m1_result: AnalysisResult | None = None
    m5_result: AnalysisResult | None = None

    # Multi-URL results. M1 and M5 are keyed by the submitted URL, M2 by "host:port".
    m1_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m2_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m5_results: dict[str, AnalysisResult] = field(default_factory=dict)
    skipped_urls: list[str] = field(default_factory=list)  # invalid, duplicate-free overflow beyond MAX_URLS

    # Message analysis
    m3_result: AnalysisResult | None = None

    # Unified results
    m4_result: AnalysisResult | None = None
    threat_report: ThreatReport | None = None
    report_submission: dict | None = None
    report_verification: dict | None = None
    report_submission_error: str | None = None
    report_submission_skipped_reason: str | None = None

    # Blockchain Integrity section: show `blockchain_message` as-is, and use `blockchain_status` for styling.
    # blockchain_status is one of: not_submitted, submitted, submitted_verified, submitted_verification_failed, failed
    blockchain_status: str = "not_submitted"
    blockchain_message: str = ""


@dataclass
class _UrlBundle:
    url: str
    m1: AnalysisResult
    m5: AnalysisResult
    tls_targets: list[tuple[str, str, int]] = field(default_factory=list)  # (scheme, host, port)


# Blockchain status message
def _first_value(mapping, keys):
    if isinstance(mapping, dict):
        for key in keys:
            if mapping.get(key) not in (None, ""):
                return mapping[key]
    return None


def _verification_ok(verification) -> bool | None:
    """True/False if the verification result says so, None if its outcome cannot be determined."""
    value = _first_value(verification, ("verified", "is_valid", "valid", "integrity_verified", "match", "matches"))
    return value if isinstance(value, bool) else None


def _blockchain_outcome(investigation: InvestigationResult) -> tuple[str, str]:
    report = investigation.threat_report
    label = report.risk_level.value.replace("_", " ").title() if report else "Unknown"
    note = "The on-chain record proves the report's contents and history have not been altered; it does not prove the report is true."

    if investigation.report_submission is not None:
        version = _first_value(investigation.report_submission, ("version",))
        tx = _first_value(investigation.report_submission, ("tx_hash", "transaction_hash", "txHash", "transaction"))
        reference = f"version {version}" if version is not None else "the latest version"
        if tx:
            reference += f", transaction {str(tx)[:66]}"
        verified = _verification_ok(investigation.report_verification)
        if verified is True:
            return "submitted_verified", (
                f"This {label} report was automatically registered on the blockchain ({reference}) and its integrity "
                f"was independently verified. {note}")
        if verified is False:
            return "submitted_verification_failed", (
                f"This {label} report was registered on the blockchain ({reference}), but integrity verification "
                f"did not pass: the on-chain commitment does not match the stored report. Treat the record as unverified.")
        return "submitted", (
            f"This {label} report was automatically registered on the blockchain ({reference}). "
            f"The verification result is available in the details. {note}")

    if investigation.report_submission_error:
        return "failed", (
            f"This {label} report qualifies for blockchain registration, but the automatic submission did not complete. "
            f"The report is still available here, but it is not recorded on-chain.")

    return "not_submitted", (
        f"Not registered on the blockchain: the assessment is {label}. Only Suspicious, High, Confirmed Malicious "
        f"or Inconclusive reports are recorded automatically.")


# URL handling
def _is_analyzable_url(url) -> bool:
    """Accepts http(s) URLs and scheme-less domains (Module 1 normalises those), and nothing else."""
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not url or len(url) > MAX_URL_CHARS or _BAD_URL_CHARS.search(url):
        return False
    has_scheme = "://" in url
    try:
        parsed = urlsplit(url if has_scheme else f"//{url}")
        host = parsed.hostname
        parsed.port  # raises ValueError on an invalid port
    except ValueError:
        return False
    if has_scheme and parsed.scheme.lower() not in ("http", "https"):
        return False
    return bool(host) and ("." in host or ":" in host)  # single-label names ("localhost", "intranet") are not public sites


def _message_urls(data) -> list[str]:
    urls = getattr(data, "urls", None)
    if isinstance(urls, list):
        return urls
    extracted = getattr(data, "urls_extracted", None)
    if isinstance(extracted, tuple) and len(extracted) > 1 and isinstance(extracted[1], list):
        return extracted[1]
    return []


def _redirect_destinations(m1_data) -> list[str]:
    chain = getattr(m1_data, "redirect_chain", None)
    if not (isinstance(chain, tuple) and len(chain) > 1 and chain[0]):
        return []
    destinations = []
    for item in chain[1]:
        if isinstance(item, str):
            destinations.append(item.rsplit(" -> ", 1)[-1].strip())  # last hop of "a -> b -> c"
    return destinations


def _tls_targets(normalized_url: str | None, m1_data) -> list[tuple[str, str, int]]:
    if m1_data is not None and getattr(m1_data, "domain_exists", (None,))[0] is False:
        return []  # nothing to handshake with
    targets = []
    for url in [normalized_url, *_redirect_destinations(m1_data)]:
        if not url or not _is_analyzable_url(url) or "://" not in url:
            continue
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        target = (scheme, parsed.hostname, port)
        if target not in targets:
            targets.append(target)
    return targets


# Per-module runners
def _run_message_analysis(message: str, investigation_id: str) -> AnalysisResult:
    """Run M3 while preserving extracted indicators if language analysis fails."""
    analyzer = None
    try:
        analyzer = MessageAnalyzer(message)
        data = analyzer.analyze()
        return AnalysisResult(investigation_id=investigation_id, module="M3", status=AnalysisStatus.COMPLETED, data=data)
    except Exception:
        logger.exception("M3 failed for %s", investigation_id)
        data = getattr(analyzer, "result", None)
        sanitized = getattr(analyzer, "sanitized_message", None) or getattr(analyzer, "text", None)
        status = AnalysisStatus.PARTIAL if sanitized and data is not None else AnalysisStatus.FAILED
        return AnalysisResult(investigation_id=investigation_id, module="M3", status=status,
                              data=data, error="Message analysis did not complete.")


def _analyze_url(url: str, investigation_id: str) -> _UrlBundle:
    """M1 and M5 for one URL. Touches no shared state, so it is safe to run in a worker thread."""
    analyzer = None
    normalized = None
    m1_data = None
    try:
        analyzer = URLAnalyzer(url)
        m1_data = analyzer.analyze()
        normalized = analyzer.normalized_url
        m1 = AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.COMPLETED, data=m1_data)
    except Exception:
        logger.exception("M1 failed for %s", investigation_id)
        normalized = getattr(analyzer, "normalized_url", None)
        m1_data = getattr(analyzer, "result", None)
        partial = bool(normalized) and m1_data is not None  # keep whatever signals were produced
        m1 = AnalysisResult(investigation_id=investigation_id, module="M1",
                            status=AnalysisStatus.PARTIAL if partial else AnalysisStatus.FAILED,
                            data=m1_data if partial else None, error="URL analysis did not complete.")

    if not normalized:
        m5 = AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.SKIPPED,
                            error="No normalised URL was available for website inspection.")
    else:
        try:
            m5 = analyze_website_security(normalized, investigation_id)
        except Exception:
            logger.exception("M5 failed for %s", investigation_id)
            m5 = AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED,
                                error="Website inspection did not complete.")

    return _UrlBundle(url=url, m1=m1, m5=m5, tls_targets=_tls_targets(normalized, m1_data))


def _analyze_tls(host: str, port: int, investigation_id: str) -> AnalysisResult:
    try:
        data = TLSAnalyzer(host, port).analyze()
        return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.COMPLETED, data=data)
    except Exception:
        logger.exception("M2 failed for %s", investigation_id)
        return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.FAILED,
                              error="TLS analysis did not complete.")


def _skipped_tls(investigation_id: str, reason: str) -> AnalysisResult:
    return AnalysisResult(investigation_id=investigation_id, module="M2", status=AnalysisStatus.SKIPPED, error=reason)


def _run_parallel(tasks: dict[str, Callable], timeout: float) -> dict:
    """Runs tasks concurrently. A task that fails or does not finish in time maps to None."""
    if not tasks:
        return {}
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = {key: pool.submit(task) for key, task in tasks.items()}
    done, _ = wait(futures.values(), timeout=timeout)
    pool.shutdown(wait=False, cancel_futures=True)  # stragglers are abandoned, not waited for
    results = {}
    for key, future in futures.items():
        try:
            results[key] = future.result() if future in done else None
        except Exception:
            logger.exception("Worker task failed")
            results[key] = None
    return results


# Entry point
def run_investigation(url: str | None = None, investigation_id: str | None = None, investigation_type: str = "url",
                      message: str | None = None, submit_to_blockchain: bool | None = None) -> InvestigationResult:
    """Run a URL, message, or combined investigation and generate one unified report.

    Blockchain submission is automatic: Suspicious, High, Confirmed Malicious and Inconclusive reports are
    registered and verified; Low Risk reports are not. `submit_to_blockchain` is deprecated and ignored; it is
    only kept so that existing callers do not break.
    """

    if investigation_type not in ("url", "message", "combined"):
        raise ValueError("investigation_type must be 'url', 'message', or 'combined'.")
    if url is not None and not isinstance(url, str):
        raise TypeError("URL must be a string.")
    if message is not None and not isinstance(message, str):
        raise TypeError("Message must be a string.")
    if investigation_type == "url" and not _is_analyzable_url(url):
        raise ValueError("A valid http(s) URL or domain must be provided for a URL investigation.")
    if investigation_type in ("message", "combined") and (not message or not message.strip()):
        raise ValueError("A message must be provided for a message or combined investigation.")
    if investigation_id is not None and not _ID_PATTERN.fullmatch(investigation_id):
        raise ValueError("investigation_id must be 8 to 64 letters, digits, hyphens or underscores.")

    investigation_id = investigation_id or str(uuid4())
    original_url = url.strip() if url else ""
    message = message[:MAX_MESSAGE_CHARS] if message else None

    investigation = InvestigationResult(
        investigation_id=investigation_id,
        original_url=original_url,
        investigation_type=investigation_type,
        message=message,
    )

    # M3: analyse the message once and extract its indicators.
    if investigation_type in ("message", "combined"):
        investigation.m3_result = _run_message_analysis(message, investigation_id)

    # Choose which URLs to analyse: explicit input first, then those found in the message.
    candidates = [original_url] if original_url else []
    if investigation.m3_result and investigation.m3_result.data:
        candidates += _message_urls(investigation.m3_result.data)

    urls: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip() if isinstance(candidate, str) else candidate
        if candidate in urls or candidate in investigation.skipped_urls:
            continue
        if _is_analyzable_url(candidate) and len(urls) < MAX_URLS:
            urls.append(candidate)
        else:
            investigation.skipped_urls.append(str(candidate)[:200])

    # M1 and M5 per URL, concurrently.
    bundles_by_url = _run_parallel(
        {u: (lambda u=u: _analyze_url(u, investigation_id)) for u in urls}, PHASE_TIMEOUT_SECONDS
    )
    bundles: list[_UrlBundle] = []
    for u in urls:
        bundle = bundles_by_url.get(u)
        if bundle is None:  # worker crashed or timed out
            bundle = _UrlBundle(
                url=u,
                m1=AnalysisResult(investigation_id=investigation_id, module="M1", status=AnalysisStatus.FAILED,
                                  error="URL analysis did not complete."),
                m5=AnalysisResult(investigation_id=investigation_id, module="M5", status=AnalysisStatus.FAILED,
                                  error="Website inspection did not complete."),
            )
        bundles.append(bundle)
        investigation.m1_results[u] = bundle.m1
        investigation.m5_results[u] = bundle.m5
    if bundles:
        investigation.m1_result = bundles[0].m1
        investigation.m5_result = bundles[0].m5

    # M2 once per unique host:port, however many URLs point at it.
    tls_tasks: dict[str, Callable] = {}
    for bundle in bundles:
        for scheme, host, port in bundle.tls_targets:
            key = f"{host}:{port}"
            if key in investigation.m2_results or key in tls_tasks:
                continue
            if scheme != "https":
                investigation.m2_results[key] = _skipped_tls(investigation_id, "TLS analysis is not applicable to HTTP URLs.")
            elif port not in TLS_ALLOWED_PORTS:
                investigation.m2_results[key] = _skipped_tls(investigation_id, "TLS analysis is limited to standard HTTPS ports.")
            else:
                tls_tasks[key] = (lambda h=host, p=port: _analyze_tls(h, p, investigation_id))
    for key, result in _run_parallel(tls_tasks, PHASE_TIMEOUT_SECONDS).items():
        investigation.m2_results[key] = result or AnalysisResult(
            investigation_id=investigation_id, module="M2", status=AnalysisStatus.FAILED,
            error="TLS analysis did not complete.")

    # M4: correlate all indicators in one database operation.
    try:
        investigation.m4_result = correlate_investigation(
            investigation_id=investigation_id,
            original_url=original_url,
            m1_result=list(investigation.m1_results.values()),
            m2_result=None,
            m3_result=investigation.m3_result,
            m5_result=list(investigation.m5_results.values()),
        )
    except Exception:
        logger.exception("M4 failed for %s", investigation_id)
        investigation.m4_result = AnalysisResult(investigation_id=investigation_id, module="M4",
                                                 status=AnalysisStatus.FAILED, error="Correlation did not complete.")

    # Assessment: one unified report.
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

    # M6: automatic for Suspicious, High, Confirmed Malicious and Inconclusive reports.
    if investigation.threat_report.risk_level not in SUBMIT_RISK_LEVELS:
        investigation.report_submission_skipped_reason = "Low Risk reports are not submitted to the blockchain."
    else:
        try:
            m6_result = submit_and_verify_report(investigation.threat_report)
            investigation.report_submission = m6_result["submission"]
            investigation.report_verification = m6_result["verification"]
        except Exception:
            logger.exception("M6 submission failed for %s", investigation_id)
            investigation.report_submission_error = "Report submission did not complete."
    investigation.blockchain_status, investigation.blockchain_message = _blockchain_outcome(investigation)

    return investigation