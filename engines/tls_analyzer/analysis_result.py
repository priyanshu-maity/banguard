from dataclasses import dataclass, field


@dataclass
class TLSAnalysisResult:
    # Connection
    https_available: tuple[bool | None, str | None] = (None, None)  # Whether a TLS handshake succeeded, and the failure reason if not
    verification_failed: tuple[bool | None, str | None] = (None, None)  # Whether certificate-chain verification failed, and the mapped reason

    # Validity
    certificate_expired: tuple[bool | None, int | None] = (None, None)  # Whether the retrieved leaf certificate is expired, and days remaining (negative if expired)
    certificate_not_yet_valid: tuple[bool | None, str | None] = (None, None)  # Whether the retrieved leaf certificate is not yet valid, and its not_before timestamp
    newly_issued_certificate: tuple[bool | None, int | None] = (None, None)  # Whether the certificate is under 7 days old, and its age in days

    # Identity
    hostname_mismatch: tuple[bool | None, list[str]] = field(default_factory=lambda: (None, []))  # Whether the host is absent from the SANs, and the SAN list

    # Issuer and trust
    self_signed: tuple[bool | None, str | None] = (None, None)  # Whether issuer equals subject, and the issuer common name
    unknown_issuer: tuple[bool | None, str | None] = (None, None)  # Whether the chain does not lead to a trusted root, and the issuer name
    distrusted_ca_match: tuple[bool | None, list[str]] = field(default_factory=lambda: (None, []))  # Whether the issuer or fingerprint is on the local distrust list, and the matched entries with source