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
