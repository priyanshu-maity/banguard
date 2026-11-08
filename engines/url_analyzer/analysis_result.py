from dataclasses import dataclass, field


@dataclass
class URLAnalysisResult:
    # URL security signals
    has_userinfo: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether credentials are embedded, and which credentials are present
    uses_ip_address: tuple[bool, str | None] = (False, None)  # Whether the hostname is an IP address, and its normalized value

    # Domain structure
    excessive_hyphens: tuple[bool, int] = (False, 0)  # Whether the domain has excessive hyphens, and their count
    excessive_subdomains: tuple[bool, int] = (False, 0)  # Whether the domain has excessive subdomains, and their count

    # Typosquatting
    typosquatting_detected: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether typosquatting is detected, and the matched brand names

    # Homograph detection
    uses_punycode: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether Punycode is used, and the affected domain components
    mixed_unicode_scripts: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether multiple Unicode scripts are mixed, and the detected scripts

    # Brand placement
    brand_in_subdomain: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether a protected brand appears in a subdomain, and the matched brand names

    # Suspicious keywords
    suspicious_keywords: tuple[bool, list[str]] = field(default_factory=lambda: (False, []))  # Whether suspicious keywords are present, and the matched keywords

    # DNS analysis
    newly_registered_domain: tuple[bool | None, int | None] = (None, None)  # Whether the domain is under 30 days old, and its age in days
    missing_a_record: tuple[bool | None, str | None] = (None, None)  # Whether the domain lacks an A record, and the reason if detected
    missing_mx_on_impersonating_domain: tuple[bool | None, str | None] = (None, None)  # Whether a brand-impersonating domain lacks an MX record, and the reason if detected