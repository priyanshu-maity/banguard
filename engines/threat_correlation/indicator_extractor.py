import ipaddress
import logging

from engines.url_analyzer.analysis_result import URLAnalysisResult
from engines.url_analyzer.url_normalizer import URLNormalizer

from .schema import IndicatorType, IndicatorSource, SharedIndicator

logger = logging.getLogger(__name__)


def _unwrap_result(result):
    """Get module data from an AnalysisResult wrapper, if present."""
    if result is None:
        return None
    return result.data if hasattr(result, "data") else result


def _as_result_list(result):
    """Normalize one or multiple module results (single, list/tuple, or dict of results) into a list of module data."""
    if result is None:
        return []

    if isinstance(result, dict):
        results = list(result.values())
    elif isinstance(result, (list, tuple)):
        results = result
    else:
        results = [result]
    return [data for item in results if (data := _unwrap_result(item)) is not None]


def _flag(data, name: str):
    """First element of a (flag, detail) tuple field, or None if absent."""
    value = getattr(data, name, None)
    return value[0] if isinstance(value, tuple) and value else None


def _detail(data, name: str):
    """Second element of a (flag, detail) tuple field, or None if absent."""
    value = getattr(data, name, None)
    return value[1] if isinstance(value, tuple) and len(value) > 1 else None


def _detail_list(data, name: str) -> list:
    detail = _detail(data, name)
    return list(detail) if isinstance(detail, (list, tuple, set)) else []


def _normalize_url(url: str) -> tuple[str | None, str | None]:
    """Return the normalized URL and its domain."""
    try:
        normalizer = URLNormalizer(url, URLAnalysisResult())
        normalized_url = normalizer.normalize()
        return normalized_url, normalizer.domain
    except Exception:  # one malformed URL must never abort extraction
        return None, None


def _normalize_domain(domain: str) -> str | None:
    """Normalize a domain name for exact comparison."""
    try:
        domain = domain.strip().rstrip(".").lower()
        if not domain:
            return None
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        return None


def _add_indicator(indicators: dict, indicator_type: IndicatorType, value: str, investigation_id: str, module: str):
    """Add an indicator while avoiding duplicate values and sources."""
    if not isinstance(value, str) or not value.strip():
        return

    value = value.strip()
    key = (indicator_type, value)

    if key not in indicators:
        indicators[key] = SharedIndicator(indicator_type=indicator_type, value=value)

    source = IndicatorSource(investigation_id=investigation_id, module=module)

    if source not in indicators[key].sources:
        indicators[key].sources.append(source)


def _add_url(indicators: dict, url: str, investigation_id: str, module: str):
    """Add a URL and its corresponding domain."""
    if not isinstance(url, str):
        return
    normalized_url, domain = _normalize_url(url)

    if normalized_url is None:
        return

    _add_indicator(indicators, IndicatorType.URL, normalized_url, investigation_id, module)

    if domain:
        _add_indicator(indicators, IndicatorType.DOMAIN, domain, investigation_id, module)


def _add_ip(indicators: dict, value: str, investigation_id: str, module: str):
    """Add an IP address in its canonical format."""
    try:
        normalized_ip = str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return

    _add_indicator(indicators, IndicatorType.IP_ADDRESS, normalized_ip, investigation_id, module)


def _extract_m1(indicators: dict, m1, investigation_id: str):
    if _flag(m1, "uses_ip_address"):
        _add_ip(indicators, _detail(m1, "uses_ip_address"), investigation_id, "M1")

    for value in _detail_list(m1, "redirect_chain"):
        if isinstance(value, str):
            url = value.rsplit(" -> ", 1)[-1]  # last hop, works for "a -> b" and "a -> b -> c"
            _add_url(indicators, url, investigation_id, "M1")

    for name in ("cross_domain_redirect", "url_shortener_detected"):
        for domain in _detail_list(m1, name):
            normalized_domain = _normalize_domain(domain)
            if normalized_domain:
                _add_indicator(indicators, IndicatorType.DOMAIN, normalized_domain, investigation_id, "M1")

    for value in _detail_list(m1, "ssrf_attempt_detected"):
        if not isinstance(value, str):
            continue
        hostname = value.split(" -> ", 1)[0].strip()
        try:
            ipaddress.ip_address(hostname)
            continue
        except ValueError:
            normalized_domain = _normalize_domain(hostname)
            if normalized_domain and normalized_domain != "localhost":
                _add_indicator(indicators, IndicatorType.DOMAIN, normalized_domain, investigation_id, "M1")


def _extract_m3(indicators: dict, m3, investigation_id: str):
    for url in getattr(m3, "urls", None) or []:
        _add_url(indicators, url, investigation_id, "M3")

    for email in getattr(m3, "email_addresses", None) or []:
        _add_indicator(indicators, IndicatorType.EMAIL, email.lower(), investigation_id, "M3")

    for phone in getattr(m3, "phone_numbers", None) or []:
        normalized_phone = "".join(char for char in phone if char.isdigit() or char == "+")
        _add_indicator(indicators, IndicatorType.PHONE_NUMBER, normalized_phone, investigation_id, "M3")


def _extract_m5(indicators: dict, m5, investigation_id: str):
    # WebsiteSecurityResult has no final_url / resolved_ips attributes:
    #   page_fetched         = (fetched: bool | None, final_url: str | None)
    #   publicly_resolvable  = (resolves_only_to_public: bool | None, addresses: list[str])
    if _flag(m5, "page_fetched") and _detail(m5, "page_fetched"):
        _add_url(indicators, _detail(m5, "page_fetched"), investigation_id, "M5")

    for ip in _detail_list(m5, "publicly_resolvable"):
        _add_ip(indicators, ip, investigation_id, "M5")


def extract_indicators(investigation_id: str, original_url: str = "", m1_result=None, m2_result=None, m3_result=None, m5_result=None) -> list[SharedIndicator]:
    """Extract and deduplicate indicators from all investigation modules.

    Each module is extracted independently, so a problem with one module's data cannot discard the others' indicators.
    """
    indicators = {}

    # Original investigation URL
    if original_url:
        _add_url(indicators, original_url, investigation_id, "INPUT")

    # M1: URL analysis, supporting multiple URLs
    for m1 in _as_result_list(m1_result):
        try:
            _extract_m1(indicators, m1, investigation_id)
        except Exception:
            logger.exception("M1 indicator extraction failed for %s", investigation_id)

    # M3: Message analysis
    m3 = _unwrap_result(m3_result)
    if m3 is not None:
        try:
            _extract_m3(indicators, m3, investigation_id)
        except Exception:
            logger.exception("M3 indicator extraction failed for %s", investigation_id)

    # M5: Website security analysis, supporting multiple URLs
    for m5 in _as_result_list(m5_result):
        try:
            _extract_m5(indicators, m5, investigation_id)
        except Exception:
            logger.exception("M5 indicator extraction failed for %s", investigation_id)

    return list(indicators.values())