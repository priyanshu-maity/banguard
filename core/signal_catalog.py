"""
What each signal means: its evidence group, likelihood ratio (LR), and the plain-language text used in reports.
Edit this file to tune the model. Nothing here touches the network.
"""
from collections.abc import Callable
from dataclasses import dataclass

from core.risk_model import Interaction


@dataclass(frozen=True)
class SignalSpec:
    module: str
    name: str  # attribute name on the module's result object
    group: str | None
    lr: float | None
    title: str
    evidence: str  # "{detail}" is replaced with the signal's detail
    impact: str
    remediation: str
    severity: str | None = None  # explicit override; otherwise derived from the LR
    lr_fn: Callable[[object], float] | None = None  # LR that depends on the detail (e.g. a detection count)
    detail_attr: str | None = None  # read the detail from a different attribute


def severity_from_lr(lr: float | None) -> str:
    if lr is None:
        return "low"
    return "high" if lr >= 8 else "medium" if lr >= 3 else "low"


def _count(detail) -> int:
    return detail if isinstance(detail, int) else 0


def _vt_malicious_lr(detail) -> float:
    n = _count(detail)
    return 7.0 if n <= 1 else 10.0 if n == 2 else 20.0  # a lone engine is often a false positive


def _vt_suspicious_lr(detail) -> float:
    n = _count(detail)
    return 1.5 if n <= 1 else 2.5 if n == 2 else 4.0


FOLLOW = "Do not open the link or enter any information on the site."

M1_SIGNALS = [
    SignalSpec("M1", "has_userinfo", "url_obfuscation", 6, "Credentials embedded in URL",
               "The URL contains embedded credentials: {detail}.",
               "Text before the '@' is not the destination. Attackers use it to make a link look like a trusted site.",
               "Check the real host after the '@' symbol. " + FOLLOW),
    SignalSpec("M1", "uses_ip_address", "url_obfuscation", 5, "Hostname is an IP address",
               "The link uses a raw IP address instead of a domain name: {detail}.",
               "Legitimate services rarely ask users to sign in at a bare IP address.", FOLLOW),
    SignalSpec("M1", "excessive_hyphens", "url_obfuscation", 1.5, "Excessive hyphens in domain",
               "The domain contains {detail} hyphens.",
               "Long hyphenated domains are often used to imitate brand names.", "Compare the domain with the organisation's official one."),
    SignalSpec("M1", "excessive_subdomains", "url_obfuscation", 1.5, "Excessive subdomains",
               "The domain has {detail} subdomain levels.",
               "Deep subdomain chains can push the real domain out of sight.", "Read the domain from right to left to find the real owner."),
    SignalSpec("M1", "suspicious_keywords", "url_obfuscation", 2, "Suspicious keywords in URL",
               "The URL contains: {detail}.",
               "Words like 'verify' or 'secure' are common in phishing links, but also appear on legitimate sites.",
               "Do not trust a link because it sounds official."),
    SignalSpec("M1", "typosquatting_detected", "domain_impersonation", 12, "Potential typosquatting detected",
               "The domain closely resembles: {detail}.",
               "Lookalike domains are used to impersonate well-known organisations and collect credentials.",
               "Type the organisation's address yourself or use its official app. " + FOLLOW),
    SignalSpec("M1", "uses_punycode", "domain_impersonation", 3, "Punycode detected",
               "Internationalised domain components: {detail}.",
               "Punycode can hide lookalike characters, though many legitimate sites use it.", "Check the domain character by character."),
    SignalSpec("M1", "mixed_unicode_scripts", "domain_impersonation", 15, "Mixed Unicode scripts detected",
               "The domain mixes writing systems: {detail}.",
               "Mixing scripts (for example Latin and Cyrillic) is a classic homograph technique.", FOLLOW),
    SignalSpec("M1", "brand_in_subdomain", "domain_impersonation", 8, "Brand name found in subdomain",
               "A protected brand appears in a subdomain: {detail}.",
               "Attackers put a brand name in front of their own domain so the link looks genuine.",
               "Check the registered domain, which is the part just before the final suffix."),
    SignalSpec("M1", "newly_registered_domain", "domain_infrastructure", 4, "Newly registered domain",
               "The domain is {detail} days old.",
               "Phishing domains are often registered days before a campaign.", "Treat unfamiliar new sites with extra caution."),
    SignalSpec("M1", "missing_a_record", "domain_infrastructure", 1.2, "Domain has no A record",
               "No A record found: {detail}.", "The domain may be inactive or misconfigured.", "No action needed on its own."),
    SignalSpec("M1", "missing_mx_on_impersonating_domain", "domain_infrastructure", 3, "Impersonating domain has no MX record",
               "A domain resembling a brand cannot receive email: {detail}.",
               "Genuine organisations' domains normally handle email; a brand lookalike that does not is suspect.", FOLLOW),
    SignalSpec("M1", "cross_domain_redirect", "redirect_abuse", 1.6, "Cross-domain redirect detected",
               "Redirects crossed to other domains: {detail}.",
               "Redirects to unrelated domains can hide the real destination, though many legitimate sites also do this.",
               "Check where the link finally lands before entering information."),
    SignalSpec("M1", "url_shortener_detected", "redirect_abuse", 2, "URL shortener detected",
               "Shortened link domains seen: {detail}.",
               "Shorteners hide the real destination.", "Expand the link in a preview tool before opening it."),
    SignalSpec("M1", "ssrf_attempt_detected", "redirect_abuse", 10, "Unsafe redirect destination detected",
               "A redirect led to a non-public address: {detail}.",
               "Redirecting to internal addresses is typical of probing or malicious infrastructure.", FOLLOW),
    SignalSpec("M1", "virustotal_malicious", "threat_intel", None, "Flagged malicious by threat-intelligence engines",
               "{detail} VirusTotal engines flagged the URL as malicious.",
               "Independent security vendors have identified this URL as malicious.", FOLLOW,
               severity="high", lr_fn=_vt_malicious_lr),
    SignalSpec("M1", "virustotal_suspicious", "threat_intel", None, "Flagged suspicious by threat-intelligence engines",
               "{detail} VirusTotal engines flagged the URL as suspicious.",
               "Some security vendors consider this URL suspicious.", "Treat the link with caution.",
               severity="medium", lr_fn=_vt_suspicious_lr),
]

M2_SIGNALS = [
    SignalSpec("M2", "distrusted_ca_match", "tls_trust", 10, "Certificate issued by a distrusted CA",
               "{detail}", "Certificates from distrusted authorities should not be relied on to prove a site's identity.",
               "Do not rely on the padlock. Verify the site another way."),
    SignalSpec("M2", "hostname_mismatch", "tls_trust", 3, "Certificate does not match the hostname",
               "The hostname is not covered by the certificate names: {detail}.",
               "Browsers warn about this because the certificate was issued for a different site.", "Do not proceed past a certificate warning."),
    SignalSpec("M2", "self_signed", "tls_trust", 2.5, "Self-signed certificate",
               "The certificate is signed by itself (issuer: {detail}).",
               "A self-signed certificate proves nothing about who runs the site.", "Do not enter sensitive data."),
    SignalSpec("M2", "unknown_issuer", "tls_trust", 2, "Certificate issuer is not trusted",
               "The chain does not lead to a trusted root (issuer: {detail}).",
               "The certificate cannot be verified against trusted authorities.", "Do not enter sensitive data."),
    SignalSpec("M2", "certificate_expired", "tls_trust", 1.5, "TLS certificate expired",
               "The certificate expired (days remaining: {detail}).",
               "Expired certificates trigger browser warnings and weaken trust in the connection.", "Site owners should renew the certificate."),
    SignalSpec("M2", "certificate_not_yet_valid", "tls_trust", 2, "TLS certificate not yet valid",
               "The certificate's start date is in the future: {detail}.",
               "This can indicate a misconfigured or forged certificate.", "Do not enter sensitive data."),
    SignalSpec("M2", "newly_issued_certificate", "tls_trust", 1.5, "Recently issued TLS certificate",
               "The certificate is {detail} days old.",
               "Attackers obtain certificates just before launching a site, but legitimate sites renew often too.", "No action needed on its own."),
]

M3_SIGNALS = [
    SignalSpec("M3", "urgency", "message_language", 1.3, "Urgency language detected", "Matched phrases: {detail}.",
               "Pressure to act quickly is a common manipulation tactic, but also appears in genuine reminders.",
               "Pause and verify through an official channel before acting."),
    SignalSpec("M3", "fear_or_threat", "message_language", 2.2, "Fear or threat language detected", "Matched phrases: {detail}.",
               "Threats of suspension, arrest or loss are used to rush people into acting.", "Contact the organisation using details from its official website."),
    SignalSpec("M3", "authority_impersonation", "message_language", 3, "Authority impersonation indicator", "Matched phrases: {detail}.",
               "Messages posing as banks, officials or employers are a common scam pattern.", "Verify the sender through an official channel."),
    SignalSpec("M3", "financial_manipulation", "message_language", 2.5, "Financial manipulation indicator", "Matched phrases: {detail}.",
               "Requests for fees, transfers or payments are a core part of many scams.", "Do not pay anything until you have verified the request."),
    SignalSpec("M3", "credential_requests", "message_language", 4, "Credential request detected", "Matched phrases: {detail}.",
               "Genuine organisations do not ask for OTPs, PINs or passwords by message.", "Never share OTPs, PINs, passwords or card details."),
    SignalSpec("M3", "reward_or_prize_lure", "message_language", 2.5, "Reward or prize lure detected", "Matched phrases: {detail}.",
               "Unexpected prizes and rewards are a common lure.", "Ignore prizes you did not enter for."),
    SignalSpec("M3", "secrecy_or_isolation", "message_language", 2.5, "Secrecy or isolation language detected", "Matched phrases: {detail}.",
               "Telling someone to keep a request secret is a common manipulation tactic.", "Discuss the request with someone you trust."),
    SignalSpec("M3", "brand_impersonation", "message_impersonation", 3, "Brand impersonation indicator", "Evidence: {detail}.",
               "The message appears to claim to come from a well-known organisation.", "Contact the organisation directly through its official website or app.",
               detail_attr="impersonation_evidence"),
]

# Website hygiene signals from Module 5. Reported as findings but not scored: missing headers say nothing about intent.
_HYGIENE = "Site owners should configure this header."
M5_SIGNALS = [
    SignalSpec("M5", "served_over_http", "transport", 1.8, "Website served over unencrypted HTTP",
               "The final response was served over plain HTTP: {detail}.",
               "Traffic can be read or modified in transit, including anything entered on the site.",
               "Do not enter sensitive data. Site owners should enable HTTPS and redirect HTTP to it.", severity="high"),
    SignalSpec("M5", "missing_hsts", None, None, "Missing or ineffective HSTS", "Observed value: {detail}.",
               "Browsers may be more exposed to protocol downgrade attacks.", _HYGIENE, severity="medium"),
    SignalSpec("M5", "missing_csp", None, None, "Missing Content Security Policy", "Observed value: {detail}.",
               "Browsers have fewer limits on where content can load from.", _HYGIENE, severity="medium"),
    SignalSpec("M5", "missing_content_type_options", None, None, "Missing or ineffective X-Content-Type-Options", "Observed value: {detail}.",
               "Some browsers may sniff content types.", _HYGIENE, severity="low"),
    SignalSpec("M5", "missing_framing_protection", None, None, "Missing clickjacking protection", "Observed value: {detail}.",
               "The site may be embedded in a hostile page.", _HYGIENE, severity="medium"),
    SignalSpec("M5", "missing_referrer_policy", None, None, "Missing or unsafe Referrer-Policy", "Observed value: {detail}.",
               "URLs may be shared with other sites more broadly than intended.", _HYGIENE, severity="low"),
    SignalSpec("M5", "missing_permissions_policy", None, None, "Missing Permissions-Policy", "Observed value: {detail}.",
               "Browser features are not explicitly restricted.", _HYGIENE, severity="low"),
]

_URL_RISK = ("domain_impersonation", "url_obfuscation", "domain_infrastructure", "redirect_abuse", "threat_intel")

INTERACTIONS = [
    Interaction("lookalike_new_domain", "Lookalike domain registered recently",
                ("domain_impersonation", "newly_registered_domain"), 3.0,
                "A domain imitating a known name was registered very recently, which is typical of a phishing campaign."),
    Interaction("lookalike_via_redirect", "Lookalike domain reached through a redirect",
                ("domain_impersonation", "redirect_abuse"), 2.5,
                "A domain imitating a known name is reached through a shortener or cross-domain redirect."),
    Interaction("message_brand_link_lookalike", "Message claims a brand and links to a lookalike domain",
                ("message_impersonation", "domain_impersonation"), 4.0,
                "The message claims to be from an organisation, and its link imitates a brand's domain."),
    Interaction("credential_request_suspicious_link", "Credential request pointing to a suspicious link",
                ("credential_requests", _URL_RISK), 4.0,
                "The message asks for credentials and contains a link with suspicious characteristics."),
    Interaction("money_lure_suspicious_link", "Payment or prize lure pointing to a suspicious link",
                (("financial_manipulation", "reward_or_prize_lure"), _URL_RISK), 3.0,
                "The message pushes a payment or prize and contains a link with suspicious characteristics."),
    Interaction("new_domain_obfuscated", "New domain with obfuscated structure",
                ("newly_registered_domain", "url_obfuscation"), 2.5,
                "A recently registered domain also uses structural tricks to look legitimate."),
    Interaction("new_domain_redirect", "New domain reached through a redirect",
                ("newly_registered_domain", "redirect_abuse"), 2.0,
                "A recently registered domain is reached through a shortener or cross-domain redirect."),
    Interaction("authority_threat_credentials", "Authority impersonation with threat and credential request",
                ("authority_impersonation", "fear_or_threat", "credential_requests"), 2.0,
                "The message combines an apparent authority, a threat, and a request for credentials."),
    Interaction("intel_with_structure", "Threat-intelligence detection backed by structural indicators",
                ("threat_intel", ("domain_impersonation", "url_obfuscation", "domain_infrastructure", "redirect_abuse")), 2.0,
                "Security vendors flagged the URL, and its structure also shows suspicious traits."),
    Interaction("campaign_with_indicators", "Known campaign link with suspicious indicators",
                ("campaign_correlation", ("domain_impersonation", "url_obfuscation", "domain_infrastructure", "message_impersonation")), 2.5,
                "Correlation linked this submission to other reports, and it also shows suspicious indicators."),
]