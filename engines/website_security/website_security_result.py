from dataclasses import dataclass, field


@dataclass
class WebsiteSecurityResult:
    # Reachability and response
    publicly_resolvable: tuple[bool | None, list[str]] = field(default_factory=lambda: (None, []))  # Whether the host resolves only to public addresses, and those addresses
    page_fetched: tuple[bool | None, str | None] = (None, None)  # Whether the page was fetched, and the final URL (query string removed)
    error_response_received: tuple[bool | None, int | None] = (None, None)  # Whether the final response was an HTTP error (4xx/5xx), and its status code
    served_over_http: tuple[bool | None, str | None] = (None, None)  # Whether the final response was served over plain HTTP, and the final URL
    final_host_differs: tuple[bool | None, str | None] = (None, None)  # Whether redirects ended on a different host than submitted, and the final host

    # Security headers (flag True = missing or ineffective; detail = observed value trimmed to 200 characters, None if absent)
    missing_hsts: tuple[bool | None, str | None] = (None, None)  # HSTS absent, or max-age missing or zero. None on plain HTTP (not applicable)
    missing_csp: tuple[bool | None, str | None] = (None, None)  # Content-Security-Policy absent
    missing_content_type_options: tuple[bool | None, str | None] = (None, None)  # X-Content-Type-Options absent or not "nosniff"
    missing_framing_protection: tuple[bool | None, str | None] = (None, None)  # No valid X-Frame-Options and no CSP frame-ancestors
    missing_referrer_policy: tuple[bool | None, str | None] = (None, None)  # Referrer-Policy absent or "unsafe-url"
    missing_permissions_policy: tuple[bool | None, str | None] = (None, None)  # Permissions-Policy absent
