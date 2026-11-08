
import ipaddress

from engines.url_analyzer.analysis_result import URLAnalysisResult
from engines.url_analyzer.url_normalizer import URLNormalizer

from .schema import IndicatorType, IndicatorSource, SharedIndicator


def _unwrap_result(result):
    """Get module data from an AnalysisResult wrapper, if present."""
    if result is None:
        return None
    return result.data if hasattr(result, "data") else result


def _as_result_list(result):
    """Normalize one or multiple module results into a list of module data."""
    if result is None:
        return []

    results = result if isinstance(result, (list, tuple)) else [result]
    return [data for item in results if (data := _unwrap_result(item)) is not None]


def _normalize_url(url: str) -> tuple[str | None, str | None]:
    """Return the normalized URL and its domain."""
    try:
        normalizer = URLNormalizer(url, URLAnalysisResult())
        normalized_url = normalizer.normalize()
        return normalized_url, normalizer.domain
    except (ValueError, AttributeError, TypeError):
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


def extract_indicators(investigation_id: str, original_url: str = "", m1_result=None, m2_result=None, m3_result=None, m5_result=None) -> list[SharedIndicator]:
    """Extract and deduplicate indicators from all investigation modules."""
    indicators = {}

    # Original investigation URL
    if original_url:
        _add_url(indicators, original_url, investigation_id, "INPUT")

    # M1: URL analysis, supporting multiple URLs
    for m1 in _as_result_list(m1_result):
        if m1.uses_ip_address[0]:
            _add_ip(indicators, m1.uses_ip_address[1], investigation_id, "M1")

        for value in m1.redirect_chain[1]:
            url = value.split(" -> ", 1)[-1] if " -> " in value else value
            _add_url(indicators, url, investigation_id, "M1")

        for domain in m1.cross_domain_redirect[1]:
            normalized_domain = _normalize_domain(domain)
            if normalized_domain:
                _add_indicator(indicators, IndicatorType.DOMAIN, normalized_domain, investigation_id, "M1")

        for domain in m1.url_shortener_detected[1]:
            normalized_domain = _normalize_domain(domain)
            if normalized_domain:
                _add_indicator(indicators, IndicatorType.DOMAIN, normalized_domain, investigation_id, "M1")

        for value in m1.ssrf_attempt_detected[1]:
            hostname = value.split(" -> ", 1)[0].strip()

            try:
                ipaddress.ip_address(hostname)
                continue
            except ValueError:
                normalized_domain = _normalize_domain(hostname)
                if normalized_domain and normalized_domain != "localhost":
                    _add_indicator(indicators, IndicatorType.DOMAIN, normalized_domain, investigation_id, "M1")

    # M3: Message analysis
    m3 = _unwrap_result(m3_result)

    if m3 is not None:
        for url in m3.urls:
            _add_url(indicators, url, investigation_id, "M3")

        for email in m3.email_addresses:
            _add_indicator(indicators, IndicatorType.EMAIL, email.lower(), investigation_id, "M3")

        for phone in m3.phone_numbers:
            normalized_phone = "".join(char for char in phone if char.isdigit() or char == "+")
            _add_indicator(indicators, IndicatorType.PHONE_NUMBER, normalized_phone, investigation_id, "M3")

    # M5: Website security analysis, supporting multiple URLs
    for m5 in _as_result_list(m5_result):
        if m5.final_url:
            _add_url(indicators, m5.final_url, investigation_id, "M5")

        for ip in m5.resolved_ips:
            _add_ip(indicators, ip, investigation_id, "M5")

    return list(indicators.values())
