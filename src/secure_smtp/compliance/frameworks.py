"""Evidence-based checks associated with TLS guidance, not compliance certification.

Passive sessions cannot establish deployment policy, certificate trust, or full
NIST/PCI/MTA-STS/DANE compliance. Missing observations remain UNKNOWN.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

ASSESSMENT_SCOPE = (
    "Observed transport checks only; not a regulatory compliance certification. "
    "Unknown evidence is not counted as passing. MTA-STS/DANE policies are not observed."
)
NIST = "NIST SP 800-52 Rev. 2"
PCI = "PCI-DSS v4.0 (Req 4.1)"
STS = "MTA-STS / DANE"


@dataclass
class ComplianceCheck:
    rule_id: str
    standard: str
    requirement: str
    description: str
    status: str  # PASS, FAIL, UNKNOWN, NOT_APPLICABLE
    remediation: str | None = None


@dataclass
class StandardSummary:
    standard_name: str
    passed: bool
    pass_count: int
    fail_count: int
    score_percentage: float | None
    checks: list[ComplianceCheck] = field(default_factory=list)
    unknown_count: int = 0
    not_applicable_count: int = 0
    status: str = "UNKNOWN"


@dataclass
class ComplianceReport:
    evaluated_at: str
    overall_status: str
    overall_score: float | None
    standards: dict[str, StandardSummary] = field(default_factory=dict)
    summary_findings: list[str] = field(default_factory=list)
    unknown_count: int = 0
    assessment_scope: str = ASSESSMENT_SCOPE

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _status(passes: int, fails: int, unknown: int) -> str:
    return "FAIL" if fails else "UNKNOWN" if unknown else "PASS" if passes else "NOT_APPLICABLE"


def _score(passes: int, fails: int, unknown: int) -> float | None:
    # Keep unobserved checks in the denominator so partial evidence cannot inflate a score.
    return round(100 * passes / (passes + fails + unknown), 1) if passes + fails else None


def _certificate_strength(certs, rule_ids):
    weak_rules = {"weak-cert-key-rsa", "weak-cert-key-ecdsa", "weak-cert-signature", "SEC-005", "SEC-006"}
    if rule_ids & weak_rules:
        return "FAIL"
    if not certs:
        return "UNKNOWN"
    unknown = False
    for cert in certs:
        algorithm = str(cert.get('public_key_algorithm') or '').upper()
        bits = cert.get('key_length_bits')
        signature = str(cert.get('signature_algorithm') or '').lower().replace('-', '')
        minimum = {'RSA': 2048, 'EC': 256, 'ECDSA': 256}.get(algorithm)
        if signature in ('md5', 'sha1') or (minimum and isinstance(bits, int) and 0 < bits < minimum):
            return "FAIL"
        if not minimum or not isinstance(bits, int) or bits <= 0 or signature not in ('sha256', 'sha384', 'sha512'):
            unknown = True
    return "UNKNOWN" if unknown else "PASS"


class ComplianceEvaluator:
    """Evaluate the observed subset of the named guidance against persisted sessions."""

    @staticmethod
    def evaluate_session(session_doc: dict[str, Any]) -> ComplianceReport:
        handshake = session_doc.get('handshake') or {}
        certs = session_doc.get('certificates') or []
        rule_ids = {f.get('rule_id') for f in session_doc.get('findings', []) if isinstance(f, dict)}
        protocol_value = session_doc.get('protocol', '')
        protocol = str(getattr(protocol_value, 'value', protocol_value)).lower()
        mode_value = session_doc.get('tls_mode', 'unknown')
        mode = str(getattr(mode_value, 'value', mode_value)).lower()
        version = str(handshake.get('tls_version_negotiated') or '').upper().replace(' ', '')
        cipher = str(handshake.get('cipher_suite_negotiated') or '').upper()
        plaintext = mode == 'none' or 'no-tls' in rule_ids or 'SEC-009' in rule_ids
        early = version in ('SSLV3', 'TLS1.0', 'TLS1.1') or bool(rule_ids & {'deprecated-tls-version', 'SEC-001'})
        modern = version in ('TLS1.2', 'TLS1.3')
        version_status = 'FAIL' if plaintext or early else 'PASS' if modern else 'UNKNOWN'
        version_description = (
            'Observed plaintext transport or a deprecated TLS version.' if version_status == 'FAIL'
            else f'Observed negotiated version: {version}.' if version_status == 'PASS'
            else 'Negotiated TLS version was not observed; no version conclusion is available.'
        )
        fs = handshake.get('forward_secrecy')
        fs_status = 'FAIL' if plaintext or fs is False or bool(rule_ids & {'no-forward-secrecy', 'SEC-003'}) else 'PASS' if fs is True else 'UNKNOWN'
        cert_status = _certificate_strength(certs, rule_ids)
        weak_cipher = bool(rule_ids & {'weak-cipher', 'SEC-002'}) or any(
            pattern in cipher for pattern in ('_RC4_', '_3DES_', '_DES_', '_NULL_', '_EXPORT_')
        )
        observed_aead = cipher.startswith('TLS_') and any(pattern in cipher for pattern in ('_GCM_', '_CHACHA20_POLY1305_'))
        cipher_status = 'FAIL' if plaintext or weak_cipher else 'PASS' if observed_aead else 'UNKNOWN'
        frameworks = {
            NIST: [
                ComplianceCheck('NIST-01', NIST, '§3.1 Minimum Protocol Version', version_description,
                                version_status, 'Review TLS version policy; require TLS 1.2 or newer.' if version_status == 'FAIL' else None),
                ComplianceCheck('NIST-02', NIST, '§3.3 Ephemeral Key Exchange', {
                    'PASS': 'Forward secrecy was observed for this connection.',
                    'FAIL': 'Observed transport does not provide forward secrecy.',
                    'UNKNOWN': 'Forward secrecy was not determined from the captured handshake.',
                }[fs_status], fs_status, 'Review ephemeral key exchange configuration.' if fs_status == 'FAIL' else None),
                ComplianceCheck('NIST-03', NIST, '§4.1 Public Key Length & Hash Security', {
                    'PASS': 'Observed certificate key size and signature hash meet these limited checks; trust was not validated.',
                    'FAIL': 'Observed certificate uses a weak key size or signature hash.',
                    'UNKNOWN': 'Certificate key or signature evidence is missing or unsupported, including encrypted TLS 1.3 certificate messages.',
                }[cert_status], cert_status, 'Review certificate key size and signature hash.' if cert_status == 'FAIL' else None),
            ],
            PCI: [
                ComplianceCheck('PCI-01', PCI, 'Req 4.1.2 Prohibit Early TLS', version_description, version_status),
                ComplianceCheck('PCI-02', PCI, 'Req 4.1.1 Strong Cryptography', {
                    'PASS': 'An AEAD cipher suite was observed; this check does not establish full PCI-DSS compliance.',
                    'FAIL': 'Plaintext or a known weak cipher suite was observed.',
                    'UNKNOWN': 'Cipher strength was not established from available handshake evidence.',
                }[cipher_status], cipher_status, 'Review negotiated cipher suites.' if cipher_status == 'FAIL' else None),
            ],
            STS: [
                ComplianceCheck('STS-01', STS, 'RFC 8461 Enforced Encryption',
                                'MTA-STS policy and enforcement were not observed. A TLS connection alone does not establish policy enforcement.',
                                'UNKNOWN' if protocol == 'smtp' else 'NOT_APPLICABLE'),
                ComplianceCheck('STS-02', STS, 'RFC 8461 Valid Certificate / RFC 7672 DANE',
                                'Certificate trust, hostname policy, DNSSEC, and TLSA bindings were not verified by this passive assessment.',
                                'UNKNOWN' if protocol == 'smtp' else 'NOT_APPLICABLE'),
            ],
        }
        summaries = {}
        messages = []
        total_passes = total_fails = total_unknown = 0
        for name, checks in frameworks.items():
            counts = Counter(check.status for check in checks)
            passed, failed, unknown = counts['PASS'], counts['FAIL'], counts['UNKNOWN']
            status = _status(passed, failed, unknown)
            summaries[name] = StandardSummary(
                standard_name=name, passed=status == 'PASS', pass_count=passed, fail_count=failed,
                score_percentage=_score(passed, failed, unknown), checks=checks,
                unknown_count=unknown, not_applicable_count=counts['NOT_APPLICABLE'], status=status,
            )
            messages.extend(f'[{name}] {check.requirement}: {check.description}' for check in checks if check.status == 'FAIL')
            total_passes += passed
            total_fails += failed
            total_unknown += unknown
        return ComplianceReport(
            evaluated_at=datetime.now(UTC).isoformat(), overall_status=_status(total_passes, total_fails, total_unknown),
            overall_score=_score(total_passes, total_fails, total_unknown), standards=summaries,
            summary_findings=messages, unknown_count=total_unknown,
        )


def evaluate_session_compliance(session_doc: dict[str, Any]) -> dict[str, Any]:
    return ComplianceEvaluator.evaluate_session(session_doc).to_dict()


def evaluate_fleet_compliance(sessions: list[dict[str, Any]]) -> dict[str, Any]:
    reports = [ComplianceEvaluator.evaluate_session(session) for session in sessions]
    totals: dict[str, Counter] = {}
    violations = []
    for report in reports:
        violations.extend(report.summary_findings)
        for name, standard in report.standards.items():
            totals.setdefault(name, Counter()).update({
                'PASS': standard.pass_count, 'FAIL': standard.fail_count, 'UNKNOWN': standard.unknown_count,
                'NOT_APPLICABLE': standard.not_applicable_count,
            })
    combined = Counter()
    for counts in totals.values():
        combined.update(counts)
    return {
        'evaluated_at': datetime.now(UTC).isoformat(),
        'overall_status': _status(combined['PASS'], combined['FAIL'], combined['UNKNOWN']) if reports else 'NOT_ASSESSED',
        'overall_score': _score(combined['PASS'], combined['FAIL'], combined['UNKNOWN']),
        'total_sessions_audited': len(sessions),
        'framework_scores': {name: _score(c['PASS'], c['FAIL'], c['UNKNOWN']) for name, c in totals.items()},
        'framework_statuses': {name: _status(c['PASS'], c['FAIL'], c['UNKNOWN']) for name, c in totals.items()},
        'framework_unknown_counts': {name: c['UNKNOWN'] for name, c in totals.items()},
        'unknown_count': combined['UNKNOWN'],
        'assessment_scope': ASSESSMENT_SCOPE,
        'top_violations': [{'violation': item, 'frequency': count} for item, count in Counter(violations).most_common(5)],
    }
