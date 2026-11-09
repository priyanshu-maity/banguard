
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from core.schema import (
    RiskLevel,
    ReportFinding,
    ReportIndicator,
    ReportEvidence,
    ThreatReport,
)

from engines.threat_correlation.indicator_extractor import extract_indicators


# ============================================================
# CONFIGURATION
# ============================================================

SEVERITY_WEIGHTS = {
    'informational': 0,
    'low': 5,
    'medium': 12,
    'high': 20,
    'critical': 30,
}

RISK_THRESHOLDS = {
    'low': 20,
    'suspicious': 40,
}

CONFIRMED_VT_MIN_ENGINES = 3
MIN_COVERAGE = 0.60


# Module signals and their severity.
# False values are ignored.
# M5 security header findings are reported but do not affect
# the maliciousness score.

SIGNALS = {
    'M1': {
        'has_userinfo': 'medium',
        'uses_ip_address': 'medium',
        'excessive_hyphens': 'low',
        'excessive_subdomains': 'low',
        'suspicious_keywords': 'low',
        'typosquatting_detected': 'high',
        'uses_punycode': 'medium',
        'mixed_unicode_scripts': 'high',
        'brand_in_subdomain': 'high',
        'newly_registered_domain': 'medium',
        'missing_a_record': 'low',
        'missing_mx_on_impersonating_domain': 'medium',
        'cross_domain_redirect': 'low',
        'url_shortener_detected': 'low',
        'ssrf_attempt_detected': 'high',
        'virustotal_malicious': 'high',
        'virustotal_suspicious': 'medium',
    },
    'M2': {
        'distrusted_ca_match': 'high',
        'hostname_mismatch': 'medium',
        'self_signed': 'low',
        'unknown_issuer': 'low',
        'certificate_expired': 'low',
        'certificate_not_yet_valid': 'low',
        'newly_issued_certificate': 'low',
    },
    'M3': {
        'urgency': 'low',
        'fear_or_threat': 'low',
        'authority_impersonation': 'medium',
        'financial_manipulation': 'low',
        'credential_requests': 'medium',
        'reward_or_prize_lure': 'low',
        'secrecy_or_isolation': 'low',
        'brand_impersonation': 'medium',
    },
    'M5': {
        'served_over_http': 'high',
        'missing_hsts': 'medium',
        'missing_csp': 'medium',
        'missing_content_type_options': 'low',
        'missing_framing_protection': 'medium',
        'missing_referrer_policy': 'low',
        'missing_permissions_policy': 'low',
    },
}

SIGNAL_TITLES = {
    'has_userinfo': 'Credentials embedded in URL',
    'uses_ip_address': 'Hostname is an IP address',
    'excessive_hyphens': 'Excessive hyphens in domain',
    'excessive_subdomains': 'Excessive subdomains',
    'suspicious_keywords': 'Suspicious keywords in URL',
    'typosquatting_detected': 'Potential typosquatting detected',
    'uses_punycode': 'Punycode detected',
    'mixed_unicode_scripts': 'Mixed Unicode scripts detected',
    'brand_in_subdomain': 'Brand name found in subdomain',
    'newly_registered_domain': 'Newly registered domain',
    'missing_a_record': 'Domain has no A record',
    'missing_mx_on_impersonating_domain': 'Impersonating domain has no MX record',
    'cross_domain_redirect': 'Cross domain redirect detected',
    'url_shortener_detected': 'URL shortener detected',
    'ssrf_attempt_detected': 'Unsafe redirect destination detected',
    'virustotal_malicious': 'Flagged malicious by VirusTotal',
    'virustotal_suspicious': 'Flagged suspicious by VirusTotal',
    'distrusted_ca_match': 'Certificate issued by a distrusted CA',
    'hostname_mismatch': 'Certificate hostname mismatch',
    'self_signed': 'Self signed certificate',
    'unknown_issuer': 'Untrusted certificate issuer',
    'certificate_expired': 'TLS certificate expired',
    'certificate_not_yet_valid': 'TLS certificate not yet valid',
    'newly_issued_certificate': 'Recently issued TLS certificate',
    'urgency': 'Urgency language detected',
    'fear_or_threat': 'Fear or threat language detected',
    'authority_impersonation': 'Authority impersonation indicator',
    'financial_manipulation': 'Financial manipulation indicator',
    'credential_requests': 'Credential request detected',
    'reward_or_prize_lure': 'Reward or prize lure detected',
    'secrecy_or_isolation': 'Secrecy or isolation language detected',
    'brand_impersonation': 'Brand impersonation indicator',
    'served_over_http': 'Website served over unencrypted HTTP',
    'missing_hsts': 'Missing or ineffective HSTS',
    'missing_csp': 'Missing Content Security Policy',
    'missing_content_type_options': 'Missing X Content Type Options',
    'missing_framing_protection': 'Missing clickjacking protection',
    'missing_referrer_policy': 'Missing or unsafe Referrer Policy',
    'missing_permissions_policy': 'Missing Permissions Policy',
}

SIGNAL_IMPACTS = {
    'typosquatting_detected': 'The domain resembles a known brand and may be used for impersonation.',
    'mixed_unicode_scripts': 'Mixing writing systems can make a malicious domain appear legitimate.',
    'brand_in_subdomain': 'Attackers can use brand names in subdomains to mislead visitors.',
    'newly_registered_domain': 'Phishing domains are often registered shortly before campaigns.',
    'virustotal_malicious': 'Security vendors have identified this URL as potentially malicious.',
    'credential_requests': 'Requests for passwords, PINs or OTPs are common phishing tactics.',
    'served_over_http': 'Traffic can be intercepted or modified in transit.',
}


# ============================================================
# DATA STRUCTURE
# ============================================================

@dataclass
class AssessmentEvidence:
    findings: list[ReportFinding] = field(default_factory=list)
    indicators: list[ReportIndicator] = field(default_factory=list)
    evidence: list[ReportEvidence] = field(default_factory=list)
    module_statuses: dict[str, str] = field(default_factory=dict)

    investigation_type: str = 'url'
    risk_level: RiskLevel | None = None
    risk_score: int = 0
    coverage: float = 0.0
    authoritative_evidence: list[str] = field(default_factory=list)


# ============================================================
# RESULT HELPERS
# ============================================================

def _unwrap(result):
    return getattr(result, 'data', None) if result is not None else None


def _result_items(results):
    if results is None:
        return []

    if isinstance(results, dict):
        return list(results.items())

    if isinstance(results, (list, tuple)):
        return [(None, result) for result in results]

    return [(None, results)]


def _status_of(result):
    if result is None:
        return 'not_provided'

    status = getattr(result, 'status', None)

    if status is None:
        return 'unknown'

    return str(getattr(status, 'value', status)).lower()


def _severity_text(severity):
    return str(getattr(severity, 'value', severity)).lower()


def _extract_flag_detail(value):
    """
    Supports:
        True
        False
        (True, detail)
        (False, detail)

    A signal is active only when its flag is True.
    """
    if isinstance(value, tuple):
        flag = value[0] if value else None
        detail = value[1] if len(value) > 1 else None
        return flag is True, detail

    if isinstance(value, bool):
        return value, None

    return False, None


def _format_detail(detail):
    if detail is None:
        return 'Detected'

    if isinstance(detail, (list, tuple, set)):
        return ', '.join(str(item) for item in detail) or 'Detected'

    return str(detail)


# ============================================================
# SIGNAL COLLECTION
# ============================================================

def _collect_signals(module, result, reference=None):
    data = _unwrap(result)

    if data is None:
        return []

    signals = []

    for name, severity in SIGNALS.get(module, {}).items():
        value = getattr(data, name, None)
        active, detail = _extract_flag_detail(value)

        if not active:
            continue

        # Some signals store their supporting detail separately.
        if module == 'M3' and name == 'brand_impersonation':
            detail = getattr(data, 'impersonation_evidence', detail)

        title = SIGNAL_TITLES.get(name, name.replace('_', ' ').title())

        description = f'{title}.'

        if detail is not None:
            description += f' Evidence: {_format_detail(detail)}.'

        finding = ReportFinding(
            title=title,
            description=description,
            severity=severity,
            source_module=module,
            impact=SIGNAL_IMPACTS.get(
                name,
                'This indicator may contribute to suspicious activity.'
            ),
            remediation='Verify the destination or request through an official channel before proceeding.',
        )

        signals.append({
            'module': module,
            'name': name,
            'severity': severity,
            'weight': SEVERITY_WEIGHTS[severity],
            'finding': finding,
            'reference': reference,
        })

    return signals


def _collect_all_signals(
    m1_result,
    m2_results,
    m3_result,
    m4_result,
    m5_result,
):
    signals = []

    for reference, result in _result_items(m1_result):
        signals.extend(_collect_signals('M1', result, reference))

    for reference, result in _result_items(m2_results):
        signals.extend(_collect_signals('M2', result, reference))

    for reference, result in _result_items(m3_result):
        signals.extend(_collect_signals('M3', result, reference))

    for reference, result in _result_items(m5_result):
        signals.extend(_collect_signals('M5', result, reference))

    return signals


# ============================================================
# CORRELATION FINDINGS
# ============================================================

def _collect_correlation(output, result):
    data = _unwrap(result)

    if data is None:
        return 0

    total_weight = 0

    for finding in getattr(data, 'findings', []):
        severity = _severity_text(
            getattr(finding, 'severity', 'low')
        )

        weight = SEVERITY_WEIGHTS.get(severity, 5)
        total_weight += weight

        output.findings.append(ReportFinding(
            title=getattr(finding, 'title', 'Correlation finding'),
            description=getattr(finding, 'description', ''),
            severity=severity,
            source_module='M4',
            impact=getattr(finding, 'impact', ''),
            remediation=getattr(finding, 'remediation', ''),
        ))

    for item in getattr(data, 'evidence', []):
        output.evidence.append(item)

    return total_weight


# ============================================================
# RISK SCORING
# ============================================================

def _calculate_score(signals, correlation_weight):
    score = sum(signal['weight'] for signal in signals)

    score += correlation_weight

    return min(score, 100)


def _authoritative_evidence(m1_result):
    evidence = []

    for reference, result in _result_items(m1_result):
        data = _unwrap(result)

        if data is None:
            continue

        value = getattr(data, 'virustotal_malicious', None)
        active, detail = _extract_flag_detail(value)

        if not active:
            continue

        count = detail if isinstance(detail, int) else None

        if count is not None and count >= CONFIRMED_VT_MIN_ENGINES:
            evidence.append(
                f'{reference or "URL"}: flagged malicious by {count} VirusTotal engines'
            )

    return evidence


def _calculate_coverage(
    m1_result,
    m2_results,
    m3_result,
    m5_result,
    investigation_type,
):
    modules = {}

    if investigation_type in ('url', 'combined'):
        if m1_result:
            modules['M1'] = m1_result

        if m2_results:
            modules['M2'] = m2_results

        if m5_result:
            modules['M5'] = m5_result

    if investigation_type in ('message', 'combined'):
        if m3_result:
            modules['M3'] = m3_result

    if not modules:
        return 0.0

    completed = 0
    total = 0

    for results in modules.values():
        for _, result in _result_items(results):
            total += 1

            status = _status_of(result)

            if status in ('completed', 'skipped'):
                completed += 1
            elif status == 'partial':
                completed += 0.5

    return completed / total if total else 0.0


# ============================================================
# EVIDENCE AND INDICATORS
# ============================================================

def _collect_evidence(output, m1_result, m5_result):
    for reference, result in _result_items(m1_result):
        data = _unwrap(result)

        if data is None:
            continue

        redirect_chain = getattr(data, 'redirect_chain', None)

        if redirect_chain:
            output.evidence.append(ReportEvidence(
                source_module='M1',
                description=f'Redirect chain for {reference or "URL"}: {redirect_chain}',
            ))

        providers = getattr(
            data,
            'threat_intelligence_provider_status',
            None,
        )

        if providers:
            output.evidence.append(ReportEvidence(
                source_module='M1',
                description=f'Threat intelligence provider status: {providers}',
            ))

    for reference, result in _result_items(m5_result):
        data = _unwrap(result)

        if data is None:
            continue

        fetched = getattr(data, 'page_fetched', None)

        if isinstance(fetched, tuple) and len(fetched) > 1 and fetched[0]:
            output.evidence.append(ReportEvidence(
                source_module='M5',
                description=f'Final inspected URL: {fetched[1]}',
            ))

    for line in output.authoritative_evidence:
        output.evidence.append(ReportEvidence(
            source_module='ASSESSMENT',
            description=f'Authoritative evidence: {line}',
        ))

    output.evidence.append(ReportEvidence(
        source_module='ASSESSMENT',
        description=f'Risk score: {output.risk_score}/100.',
    ))

    output.evidence.append(ReportEvidence(
        source_module='ASSESSMENT',
        description=f'Evidence coverage: {output.coverage:.0%}.',
    ))


def _collect_indicators(
    output,
    investigation_id,
    original_url,
    m1_result,
    m3_result,
    m5_result,
):
    try:
        extracted = extract_indicators(
            investigation_id=investigation_id,
            original_url=original_url or '',
            m1_result=[
                result for _, result in _result_items(m1_result)
            ],
            m3_result=m3_result,
            m5_result=[
                result for _, result in _result_items(m5_result)
            ],
        )

        for item in extracted:
            for source in item.sources:
                indicator_type = getattr(
                    item.indicator_type,
                    'value',
                    item.indicator_type,
                )

                output.indicators.append(ReportIndicator(
                    indicator_type=str(indicator_type),
                    value=item.value,
                    source_module=source.module,
                ))

    except Exception:
        # Indicator extraction is supplementary.
        # It should not prevent the threat report from being generated.
        return


# ============================================================
# RISK CLASSIFICATION
# ============================================================

def _classify_score(score, coverage, authoritative_evidence):
    if authoritative_evidence:
        return RiskLevel.CONFIRMED_MALICIOUS

    if score >= RISK_THRESHOLDS['suspicious']:
        return RiskLevel.HIGH

    if score >= RISK_THRESHOLDS['low']:
        return RiskLevel.SUSPICIOUS

    if coverage < MIN_COVERAGE:
        return RiskLevel.INCONCLUSIVE

    return RiskLevel.LOW


def classify_risk(assessment):
    return assessment.risk_level or RiskLevel.INCONCLUSIVE


# ============================================================
# PUBLIC ASSESSMENT FUNCTION
# ============================================================

def collect_assessment_evidence(
    investigation_id,
    original_url='',
    m1_result=None,
    m2_results=None,
    m3_result=None,
    m4_result=None,
    m5_result=None,
    investigation_type='url',
):
    if investigation_type not in ('url', 'message', 'combined'):
        raise ValueError(
            'investigation_type must be url, message, or combined.'
        )

    output = AssessmentEvidence(
        investigation_type=investigation_type,
    )

    # Record module statuses.
    for module, results in (
        ('M1', m1_result),
        ('M2', m2_results),
        ('M3', m3_result),
        ('M5', m5_result),
        ('M4', m4_result),
    ):
        for reference, result in _result_items(results):
            key = f'{module}:{reference}' if reference else module
            output.module_statuses[key] = _status_of(result)

        if not _result_items(results):
            output.module_statuses[module] = 'not_provided'

    # Collect findings and their severity weights.
    signals = _collect_all_signals(
        m1_result,
        m2_results,
        m3_result,
        m4_result,
        m5_result,
    )

    for signal in signals:
        output.findings.append(signal['finding'])

    # Include M4 correlation findings.
    correlation_weight = _collect_correlation(
        output,
        m4_result,
    )

    # Calculate score.
    output.risk_score = _calculate_score(
        signals,
        correlation_weight,
    )

    # Check authoritative threat intelligence.
    output.authoritative_evidence = _authoritative_evidence(
        m1_result,
    )

    # Calculate coverage and classify risk.
    output.coverage = _calculate_coverage(
        m1_result,
        m2_results,
        m3_result,
        m5_result,
        investigation_type,
    )

    output.risk_level = _classify_score(
        output.risk_score,
        output.coverage,
        output.authoritative_evidence,
    )

    # Collect supporting evidence and indicators.
    _collect_evidence(
        output,
        m1_result,
        m5_result,
    )

    _collect_indicators(
        output,
        investigation_id,
        original_url,
        m1_result,
        m3_result,
        m5_result,
    )

    return output


# ============================================================
# THREAT REPORT GENERATION
# ============================================================

def create_threat_report(investigation_id, assessment):
    risk_level = classify_risk(assessment)

    summaries = {
        RiskLevel.LOW: "No significant malicious indicators were identified.",
        RiskLevel.SUSPICIOUS: "Suspicious indicators were identified. Further investigation is recommended.",
        RiskLevel.HIGH: "Multiple strong indicators of potentially malicious activity were identified.",
        RiskLevel.CONFIRMED_MALICIOUS: "Threat intelligence confirmed malicious activity.",
        RiskLevel.INCONCLUSIVE: "Available analysis was insufficient to reach a reliable security assessment.",
    }

    summary = summaries[risk_level]

    summary += f' Risk score: {assessment.risk_score}/100.'
    summary += f' Evidence coverage: {assessment.coverage:.0%}.'

    if assessment.findings:
        summary += f' {len(assessment.findings)} findings were recorded.'
    else:
        summary += ' No findings were recorded.'

    if assessment.indicators:
        summary += f' {len(assessment.indicators)} threat indicators were recorded.'

    incomplete = [
        f'{module}: {status}'
        for module, status in assessment.module_statuses.items()
        if status in ('partial', 'failed')
    ]

    if incomplete:
        summary += ' Incomplete analyses: ' + ', '.join(incomplete) + '.'

    return ThreatReport(
        report_id=str(uuid4()),
        investigation_id=investigation_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        risk_level=risk_level,
        summary=summary,
        findings=list(assessment.findings),
        indicators=list(assessment.indicators),
        evidence=list(assessment.evidence),
    )


# ============================================================
# BLOCKCHAIN REPORT SUBMISSION
# ============================================================

def submit_and_verify_report(report):
    from engines.threat_intelligence.report_manager import submit_report
    from engines.threat_intelligence.verification import verify_report

    submission = submit_report(report)

    verification = verify_report(
        report.report_id,
        submission['version'],
    )

    return {
        'submission': submission,
        'verification': verification,
    }
