import ipaddress
from urllib.parse import urlparse

from engines.url_analyzer.analysis_result import URLAnalysisResult
from engines.url_analyzer.url_normalizer import URLNormalizer

from .schema import (
    IndicatorType,
    IndicatorSource,
    SharedIndicator,
)


def _unwrap_result(result):
    """Get module data from an AnalysisResult wrapper, if present."""
    if result is None:
        return None

    if hasattr(result, "data"):
        return result.data

    return result

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

def _add_indicator(indicators: dict, indicator_type: IndicatorType, value: str, investigation_id: str, module: str,):
    """Add an indicator while avoiding duplicate values and sources."""
    if not isinstance(value, str) or not value.strip():
        return

    value = value.strip()
    key = (indicator_type, value)

    if key not in indicators:
        indicators[key] = SharedIndicator(indicator_type=indicator_type, value=value,)

    source = IndicatorSource(investigation_id=investigation_id, module=module,)

    if source not in indicators[key].sources:
        indicators[key].sources.append(source)

def _add_url(indicators: dict, url: str, investigation_id: str, module: str,):
    """Add a URL and its corresponding domain."""
    normalized_url, domain = _normalize_url(url)

    if normalized_url is None:
        return

    _add_indicator(indicators, IndicatorType.URL, normalized_url, investigation_id, module,)

    if domain:
        _add_indicator(indicators, IndicatorType.DOMAIN, domain, investigation_id, module,)

def _add_ip(indicators: dict, value: str, investigation_id: str, module: str,):
    """Add an IP address in its canonical format."""
    try:
        normalized_ip = str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return

    _add_indicator(indicators, IndicatorType.IP_ADDRESS, normalized_ip, investigation_id, module,)