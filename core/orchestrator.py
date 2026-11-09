import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from uuid import uuid4

from core import progress
from core.schema import AnalysisResult, AnalysisStatus, RiskLevel, ThreatReport
from core.assessment_engine import (
    collect_assessment_evidence,
    create_threat_report,
    submit_and_verify_report,
)
from engines.url_analyzer.url_analyzer import URLAnalyzer
from engines.tls_analyzer.tls_analyzer import TLSAnalyzer
from engines.website_security.website_security import analyze_website_security
from engines.message_analyzer.message_analyzer import MessageAnalyzer
from engines.threat_correlation.correlation_engine import correlate_investigation

logger = logging.getLogger(__name__)

MAX_URLS = 5
MAX_WORKERS = 4
PHASE_TIMEOUT_SECONDS = 90
MAX_MESSAGE_CHARS = 10_000
MAX_URL_CHARS = 2048
TLS_ALLOWED_PORTS = (443, 8443)

SUBMIT_RISK_LEVELS = (
    RiskLevel.SUSPICIOUS,
    RiskLevel.HIGH,
    RiskLevel.CONFIRMED_MALICIOUS,
    RiskLevel.INCONCLUSIVE,
)

_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,64}")
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f\\]")


@dataclass
class InvestigationResult:
    investigation_id: str
    original_url: str
    investigation_type: str = "url"
    message: str | None = None

    m1_result: AnalysisResult | None = None
    m5_result: AnalysisResult | None = None

    m1_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m2_results: dict[str, AnalysisResult] = field(default_factory=dict)
    m5_results: dict[str, AnalysisResult] = field(default_factory=dict)
    skipped_urls: list[str] = field(default_factory=list)

    m3_result: AnalysisResult | None = None

    m4_result: AnalysisResult | None = None
    threat_report: ThreatReport | None = None
    report_submission: dict | None = None
    report_verification: dict | None = None
    report_submission_error: str | None = None
    report_submission_skipped_reason: str | None = None

    blockchain_status: str = "not_submitted"
    blockchain_message: str = ""


@dataclass
class _UrlBundle:
    url: str
    m1: AnalysisResult
    m5: AnalysisResult
    tls_targets: list[tuple[str, str, int]] = field(default_factory=list)


# Blockchain status message

def _first_value(mapping, keys):
    if isinstance(mapping, dict):
        for key in keys:
            if mapping.get(key) not in (None, ""):
                return mapping[key]
    return None


def _verification_ok(verification) -> bool | None:
    value = _first_value(
        verification,
        ("verified", "is_valid", "valid", "integrity_verified", "match", "matches"),
    )
    return value if isinstance(value, bool) else None


def _blockchain_outcome(investigation: InvestigationResult) -> tuple[str, str]:
    report = investigation.threat_report
    label = report.risk_level.value.replace("_", " ").title() if report else "Unknown"
    note = (
        "The on-chain record proves the report's contents and history have not "
        "been altered; it does not prove the report is true."
    )

    if investigation.report_submission is not None:
        version = _first_value(investigation.report_submission, ("version",))
        tx = _first_value(
            investigation.report_submission,
            ("tx_hash", "transaction_hash", "txHash", "transaction"),
        )

        reference = f"version {version}" if version is not None else "the latest version"

        if tx:
            reference += f", transaction {str(tx)[:66]}"

        verified = _verification_ok(investigation.report_verification)

        if verified is True:
            return "submitted_verified", (
                f"This {label} report was automatically registered on the blockchain "
                f"({reference}) and its integrity was independently verified. {note}"
            )

        if verified is False:
            return "submitted_verification_failed", (
                f"This {label} report was registered on the blockchain ({reference}), "
                "but integrity verification did not pass: the on-chain commitment "
                "does not match the stored report. Treat the record as unverified."
            )

        return "submitted", (
            f"This {label} report was automatically registered on the blockchain "
            f"({reference}). The verification result is available in the details. {note}"
        )

    if investigation.report_submission_error:
        return "failed", (
            f"This {label} report qualifies for blockchain registration, but the "
            "automatic submission did not complete. The report is still available "
            "here, but it is not recorded on-chain."
        )

    return "not_submitted", (
        f"Not registered on the blockchain: the assessment is {label}. Only "
        "Suspicious, High, Confirmed Malicious or Inconclusive reports are "
        "recorded automatically."
    )


# URL handling

def _is_analyzable_url(url) -> bool:
    if not isinstance(url, str):
        return False

    url = url.strip()

    if not url or len(url) > MAX_URL_CHARS or _BAD_URL_CHARS.search(url):
        return False

    has_scheme = "://" in url

    try:
        parsed = urlsplit(url if has_scheme else f"//{url}")
        host = parsed.hostname
        parsed.port
    except ValueError:
        return False

    if has_scheme and parsed.scheme.lower() not in ("http", "https"):
        return False

    return bool(host) and ("." in host or ":" in host)


def _message_urls(data) -> list[str]:
    urls = getattr(data, "urls", None)

    if isinstance(urls, list):
        return urls

    extracted = getattr(data, "urls_extracted", None)

    if (
        isinstance(extracted, tuple)
        and len(extracted) > 1
        and isinstance(extracted[1], list)
    ):
        return extracted[1]

    return []


def _redirect_destinations(m1_data) -> list[str]:
    chain = getattr(m1_data, "redirect_chain", None)

    if not (isinstance(chain, tuple) and len(chain) > 1 and chain[0]):
        return []

    destinations = []

    for item in chain[1]:
        if isinstance(item, str):
            destinations.append(item.rsplit(" -> ", 1)[-1].strip())

    return destinations


def _tls_targets(
    normalized_url: str | None,
    m1_data,
) -> list[tuple[str, str, int]]:

    if m1_data is not None and getattr(m1_data, "domain_exists", (None,))[0] is False:
        return []

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
    analyzer = None

    try:
        analyzer = MessageAnalyzer(message)
        data = analyzer.analyze()

        return AnalysisResult(
            investigation_id=investigation_id,
            module="M3",
            status=AnalysisStatus.COMPLETED,
            data=data,
        )

    except Exception:
        logger.exception("M3 failed for %s", investigation_id)

        data = getattr(analyzer, "result", None)
        sanitized = (
            getattr(analyzer, "sanitized_message", None)
            or getattr(analyzer, "text", None)
        )

        status = (
            AnalysisStatus.PARTIAL
            if sanitized and data is not None
            else AnalysisStatus.FAILED
        )

        return AnalysisResult(
            investigation_id=investigation_id,
            module="M3",
            status=status,
            data=data,
            error="Message analysis did not complete.",
        )


def _analyze_url(url: str, investigation_id: str) -> _UrlBundle:
    """M1 and M5 for one URL. Runs inside a worker thread."""

    analyzer = None
    normalized = None
    m1_data = None

    try:
        analyzer = URLAnalyzer(url)
        m1_data = analyzer.analyze()
        normalized = analyzer.normalized_url

        m1 = AnalysisResult(
            investigation_id=investigation_id,
            module="M1",
            status=AnalysisStatus.COMPLETED,
            data=m1_data,
        )

    except Exception:
        logger.exception("M1 failed for %s", investigation_id)

        normalized = getattr(analyzer, "normalized_url", None)
        m1_data = getattr(analyzer, "result", None)

        partial = bool(normalized) and m1_data is not None

        m1 = AnalysisResult(
            investigation_id=investigation_id,
            module="M1",
            status=AnalysisStatus.PARTIAL if partial else AnalysisStatus.FAILED,
            data=m1_data if partial else None,
            error="URL analysis did not complete.",
        )

    finally:
        progress.tick(investigation_id, "url_m1")

    # M1 completed, M5 starts.
    progress.start(investigation_id, "url_m5")

    if not normalized:
        m5 = AnalysisResult(
            investigation_id=investigation_id,
            module="M5",
            status=AnalysisStatus.SKIPPED,
            error="No normalised URL was available for website inspection.",
        )

    else:
        try:
            m5 = analyze_website_security(normalized, investigation_id)

        except Exception:
            logger.exception("M5 failed for %s", investigation_id)

            m5 = AnalysisResult(
                investigation_id=investigation_id,
                module="M5",
                status=AnalysisStatus.FAILED,
                error="Website inspection did not complete.",
            )

    progress.tick(investigation_id, "url_m5")

    return _UrlBundle(
        url=url,
        m1=m1,
        m5=m5,
        tls_targets=_tls_targets(normalized, m1_data),
    )


def _analyze_tls(host: str, port: int, investigation_id: str) -> AnalysisResult:
    try:
        data = TLSAnalyzer(host, port).analyze()

        return AnalysisResult(
            investigation_id=investigation_id,
            module="M2",
            status=AnalysisStatus.COMPLETED,
            data=data,
        )

    except Exception:
        logger.exception("M2 failed for %s", investigation_id)

        return AnalysisResult(
            investigation_id=investigation_id,
            module="M2",
            status=AnalysisStatus.FAILED,
            error="TLS analysis did not complete.",
        )

    finally:
        progress.tick(investigation_id, "tls")


def _skipped_tls(investigation_id: str, reason: str) -> AnalysisResult:
    return AnalysisResult(
        investigation_id=investigation_id,
        module="M2",
        status=AnalysisStatus.SKIPPED,
        error=reason,
    )


def _run_parallel(tasks: dict[str, Callable], timeout: float) -> dict:
    """Runs tasks concurrently. A task that fails or times out maps to None."""

    if not tasks:
        return {}

    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    futures = {
        key: pool.submit(task)
        for key, task in tasks.items()
    }

    done, _ = wait(futures.values(), timeout=timeout)

    pool.shutdown(wait=False, cancel_futures=True)

    results = {}

    for key, future in futures.items():
        try:
            results[key] = future.result() if future in done else None

        except Exception:
            logger.exception("Worker task failed")
            results[key] = None

    return results


# Investigation implementation

def _run_investigation(
    url: str | None = None,
    investigation_id: str | None = None,
    investigation_type: str = "url",
    message: str | None = None,
    submit_to_blockchain: bool | None = None,
) -> InvestigationResult:

    """Run a URL, message, or combined investigation and generate one unified report."""

    if investigation_type not in ("url", "message", "combined"):
        raise ValueError(
            "investigation_type must be 'url', 'message', or 'combined'."
        )

    if url is not None and not isinstance(url, str):
        raise TypeError("URL must be a string.")

    if message is not None and not isinstance(message, str):
        raise TypeError("Message must be a string.")

    if investigation_type == "url" and not _is_analyzable_url(url):
        raise ValueError(
            "A valid http(s) URL or domain must be provided for a URL investigation."
        )

    if investigation_type in ("message", "combined") and (
        not message or not message.strip()
    ):
        raise ValueError(
            "A message must be provided for a message or combined investigation."
        )

    if investigation_id is not None and not _ID_PATTERN.fullmatch(investigation_id):
        raise ValueError(
            "investigation_id must be 8 to 64 letters, digits, hyphens or underscores."
        )

    investigation_id = investigation_id or str(uuid4())

    original_url = url.strip() if url else ""
    message = message[:MAX_MESSAGE_CHARS] if message else None

    investigation = InvestigationResult(
        investigation_id=investigation_id,
        original_url=original_url,
        investigation_type=investigation_type,
        message=message,
    )

    # Initialize progress tracking.
    progress.begin(investigation_id, investigation_type)

    # M3: Message analysis.
    if investigation_type in ("message", "combined"):
        progress.start(investigation_id, "m3")

        investigation.m3_result = _run_message_analysis(
            message,
            investigation_id,
        )

        progress.done(investigation_id, "m3")

    # Choose URLs: explicit input first, then links extracted from the message.
    candidates = [original_url] if original_url else []

    if investigation.m3_result and investigation.m3_result.data:
        candidates += _message_urls(investigation.m3_result.data)

    urls: list[str] = []

    for candidate in candidates:
        candidate = (
            candidate.strip()
            if isinstance(candidate, str)
            else candidate
        )

        if candidate in urls or candidate in investigation.skipped_urls:
            continue

        if _is_analyzable_url(candidate) and len(urls) < MAX_URLS:
            urls.append(candidate)

        else:
            investigation.skipped_urls.append(str(candidate)[:200])

    # Tell the tracker how many URLs will be analysed.
    progress.urls_found(
        investigation_id,
        len(urls),
        from_message=investigation_type == "message",
    )

    # M1 and M5: Concurrent URL analysis.
    bundles_by_url = _run_parallel(
        {
            u: (
                lambda u=u: _analyze_url(u, investigation_id)
            )
            for u in urls
        },
        PHASE_TIMEOUT_SECONDS,
    )

    bundles: list[_UrlBundle] = []

    for u in urls:
        bundle = bundles_by_url.get(u)

        if bundle is None:
            bundle = _UrlBundle(
                url=u,
                m1=AnalysisResult(
                    investigation_id=investigation_id,
                    module="M1",
                    status=AnalysisStatus.FAILED,
                    error="URL analysis did not complete.",
                ),
                m5=AnalysisResult(
                    investigation_id=investigation_id,
                    module="M5",
                    status=AnalysisStatus.FAILED,
                    error="Website inspection did not complete.",
                ),
            )

        bundles.append(bundle)

        investigation.m1_results[u] = bundle.m1
        investigation.m5_results[u] = bundle.m5

    if bundles:
        investigation.m1_result = bundles[0].m1
        investigation.m5_result = bundles[0].m5

    # Report redirect activity.
    redirect_count = sum(
        len(_redirect_destinations(getattr(bundle.m1, "data", None)))
        for bundle in bundles
    )

    progress.redirects(investigation_id, redirect_count)

    # M2: TLS analysis, once per unique host and port.
    tls_tasks: dict[str, Callable] = {}

    for bundle in bundles:
        for scheme, host, port in bundle.tls_targets:
            key = f"{host}:{port}"

            if key in investigation.m2_results or key in tls_tasks:
                continue

            if scheme != "https":
                investigation.m2_results[key] = _skipped_tls(
                    investigation_id,
                    "TLS analysis is not applicable to HTTP URLs.",
                )

            elif port not in TLS_ALLOWED_PORTS:
                investigation.m2_results[key] = _skipped_tls(
                    investigation_id,
                    "TLS analysis is limited to standard HTTPS ports.",
                )

            else:
                tls_tasks[key] = (
                    lambda h=host, p=port: _analyze_tls(
                        h,
                        p,
                        investigation_id,
                    )
                )

    # Set the expected number of certificate checks.
    progress.tls_planned(investigation_id, len(tls_tasks))

    tls_results = _run_parallel(
        tls_tasks,
        PHASE_TIMEOUT_SECONDS,
    )

    for key, result in tls_results.items():
        investigation.m2_results[key] = result or AnalysisResult(
            investigation_id=investigation_id,
            module="M2",
            status=AnalysisStatus.FAILED,
            error="TLS analysis did not complete.",
        )

    # M4: Threat correlation.
    progress.start(investigation_id, "corr")

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

        investigation.m4_result = AnalysisResult(
            investigation_id=investigation_id,
            module="M4",
            status=AnalysisStatus.FAILED,
            error="Correlation did not complete.",
        )

    progress.done(investigation_id, "corr")

    # Assessment: Generate one unified threat report.
    progress.start(investigation_id, "assess")

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

    investigation.threat_report = create_threat_report(
        investigation_id,
        assessment,
    )

    progress.done(investigation_id, "assess")

    # M6: Automatic blockchain submission.
    if investigation.threat_report.risk_level not in SUBMIT_RISK_LEVELS:
        investigation.report_submission_skipped_reason = (
            "Low Risk reports are not submitted to the blockchain."
        )

        progress.skip(investigation_id, "chain")

    else:
        progress.start(investigation_id, "chain")

        try:
            m6_result = submit_and_verify_report(
                investigation.threat_report
            )

            investigation.report_submission = m6_result["submission"]
            investigation.report_verification = m6_result["verification"]

        except Exception:
            logger.exception(
                "M6 submission failed for %s",
                investigation_id,
            )

            investigation.report_submission_error = (
                "Report submission did not complete."
            )

        progress.done(investigation_id, "chain")

    investigation.blockchain_status, investigation.blockchain_message = (
        _blockchain_outcome(investigation)
    )

    # Mark the entire investigation as finished.
    progress.finish(investigation_id)

    return investigation


# Public entry point

def run_investigation(
    url: str | None = None,
    investigation_id: str | None = None,
    investigation_type: str = "url",
    message: str | None = None,
    submit_to_blockchain: bool | None = None,
) -> InvestigationResult:

    """Public entry point with progress failure handling and cleanup."""

    try:
        return _run_investigation(
            url=url,
            investigation_id=investigation_id,
            investigation_type=investigation_type,
            message=message,
            submit_to_blockchain=submit_to_blockchain,
        )

    except BaseException:
        progress.fail_current()
        raise

    finally:
        progress.release_current()
