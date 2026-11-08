from dataclasses import dataclass, field


@dataclass
class URLAnalysisResult:
    # URL security signals
    has_userinfo: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))
    uses_ip_address: tuple[bool, str | None] = (False, None)

    # Domain structure
    excessive_hyphens: tuple[bool, int] = (False, 0)
    excessive_subdomains: tuple[bool, int] = (False, 0)

    # Typosquatting
    typosquatting_detected: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))

    # Homograph detection
    uses_punycode: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))
    mixed_unicode_scripts: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))

    # Brand placement
    brand_in_subdomain: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))

    # Suspicious keywords
    suspicious_keywords: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))
