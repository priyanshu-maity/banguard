
from core.assessment_engine import AssessmentEvidence, classify_risk
from core.schema import ReportFinding, RiskLevel


def make_finding(title: str, source_module: str = "M5", severity: str = "MEDIUM") -> ReportFinding:
    return ReportFinding(title=title, description=f"Test finding: {title}", severity=severity, source_module=source_module)


def make_assessment(*findings: ReportFinding) -> AssessmentEvidence:
    return AssessmentEvidence(
        findings=list(findings),
        module_statuses={"M1": "completed", "M5": "completed", "M2:https://example.com/": "completed"},
    )


def test_missing_security_headers_do_not_increase_phishing_risk():
    findings = [
        make_finding("Missing HSTS header"),
        make_finding("Missing Content Security Policy"),
        make_finding("Missing X-Content-Type-Options header"),
        make_finding("Missing X-Frame-Options header"),
        make_finding("Missing Referrer-Policy header"),
        make_finding("Missing Permissions-Policy header"),
    ]

    assert classify_risk(make_assessment(*findings)) == RiskLevel.LOW


def test_explicit_phishing_language_and_password_field_are_suspicious():
    assessment = make_assessment(
        make_finding("Explicit phishing or social-engineering indicators", severity="HIGH"),
        make_finding("Password field outside a detected form"),
    )

    assert classify_risk(assessment) == RiskLevel.SUSPICIOUS


def test_external_sensitive_form_submission_is_suspicious():
    assessment = make_assessment(
        make_finding("Sensitive form submits to external domain", severity="HIGH"),
    )

    assert classify_risk(assessment) == RiskLevel.SUSPICIOUS


def test_two_independent_strong_indicators_are_high_risk():
    assessment = make_assessment(
        make_finding("Potential typosquatting detected", source_module="M1", severity="HIGH"),
        make_finding("Sensitive form submits to external domain", severity="HIGH"),
    )

    assert classify_risk(assessment) == RiskLevel.HIGH
