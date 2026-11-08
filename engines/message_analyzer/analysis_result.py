from dataclasses import dataclass, field


@dataclass
class MessageAnalysisResult:
    # Extracted indicators
    urls: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)

    # Language signals
    urgency: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    fear_or_threat: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    authority_impersonation: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    financial_manipulation: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    credential_requests: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    reward_or_prize_lure: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))
    secrecy_or_isolation: tuple[bool, list[str]] = field(default_factory=lambda: (None, []))

    # Impersonation signals
    claimed_brand: str | None = None
    sender_domain: str | None = None
    brand_impersonation: bool = False
    impersonation_evidence: list[str] = field(default_factory=list)
