"""Observed compliance checks use persisted schemas and preserve missing evidence."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secure_smtp.api.auth import Principal, verify_api_key
from secure_smtp.api.main import app
from secure_smtp.compliance.frameworks import (
    NIST,
    PCI,
    STS,
    ComplianceEvaluator,
    evaluate_fleet_compliance,
)
from secure_smtp.db.models import Certificate, ProtocolType, Session, TLSHandshake, TLSMode


@pytest.fixture
def modern_session():
    return Session(
        id=1, host_id=1, src_ip="192.0.2.1", dst_ip="192.0.2.2", src_port=40000, dst_port=465,
        protocol=ProtocolType.SMTP, tls_mode=TLSMode.IMPLICIT,
        handshake=TLSHandshake(tls_version_negotiated="TLS1.3", forward_secrecy=True,
                               cipher_suite_negotiated="TLS_AES_256_GCM_SHA384"),
        certificates=[Certificate(public_key_algorithm="RSA", key_length_bits=2048, signature_algorithm="sha256")],
    ).model_dump()


def check(report, check_id):
    return next(c for standard in report.standards.values() for c in standard.checks if c.rule_id == check_id)


def test_real_persisted_tls_schema_passes_observed_checks_without_policy_claim(modern_session):
    assert "has_tls" not in modern_session
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert report.standards[NIST].passed is True
    assert report.standards[PCI].passed is True
    assert report.standards[NIST].score_percentage == 100
    assert report.standards[STS].passed is False
    assert report.standards[STS].status == "UNKNOWN"
    assert report.standards[STS].score_percentage is None
    assert report.overall_status == "UNKNOWN"
    assert report.unknown_count == 2
    assert report.overall_score == 71.4
    assert report.summary_findings == []
    assert "not a regulatory compliance certification" in report.assessment_scope


@pytest.mark.parametrize("version", ["TLS1.2", "TLS1.3", "TLS 1.2", "TLS 1.3"])
def test_canonical_and_legacy_version_spelling(modern_session, version):
    modern_session['handshake']['tls_version_negotiated'] = version
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert check(report, 'NIST-01').status == 'PASS'
    assert check(report, 'PCI-01').status == 'PASS'


def test_deprecated_tls_and_actual_weak_rule_ids_fail(modern_session):
    modern_session['handshake'].update(tls_version_negotiated='TLS1.0', forward_secrecy=False,
                                       cipher_suite_negotiated='TLS_RSA_WITH_RC4_128_SHA')
    modern_session['findings'] = [{'rule_id': rule} for rule in ['deprecated-tls-version', 'weak-cipher', 'no-forward-secrecy', 'weak-cert-key-rsa']]
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert report.overall_status == 'FAIL'
    assert report.standards[NIST].fail_count == 3
    assert report.standards[PCI].fail_count == 2
    assert report.overall_score == 0


@pytest.mark.parametrize('rule', ['weak-cert-key-rsa', 'weak-cert-key-ecdsa', 'weak-cert-signature'])
def test_real_certificate_rule_ids_override_apparent_clean_metadata(modern_session, rule):
    modern_session['findings'] = [{'rule_id': rule}]
    assert check(ComplianceEvaluator.evaluate_session(modern_session), 'NIST-03').status == 'FAIL'


def test_weak_raw_certificate_metadata_is_not_assumed_valid_without_rules(modern_session):
    modern_session['certificates'][0]['key_length_bits'] = 1024
    assert check(ComplianceEvaluator.evaluate_session(modern_session), 'NIST-03').status == 'FAIL'


def test_absent_tls13_certificate_is_unknown_not_valid_or_plaintext(modern_session):
    modern_session['certificates'] = []
    modern_session['handshake']['visibility_limited'] = True
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert check(report, 'NIST-01').status == 'PASS'
    assert check(report, 'NIST-03').status == 'UNKNOWN'
    assert report.standards[NIST].passed is False
    assert report.standards[NIST].fail_count == 0
    assert report.standards[NIST].unknown_count == 1
    assert 'unencrypted connection' not in check(report, 'NIST-03').description


def test_empty_certificate_and_handshake_fields_remain_unknown(modern_session):
    modern_session['handshake'] = TLSHandshake().model_dump()
    modern_session['certificates'] = [Certificate().model_dump()]
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert report.overall_status == 'UNKNOWN'
    assert report.overall_score is None
    assert report.unknown_count == 7
    assert all(standard.pass_count == 0 for standard in report.standards.values())
    assert report.summary_findings == []


def test_explicit_unknown_transport_is_not_plaintext_failure():
    report = ComplianceEvaluator.evaluate_session({'protocol': 'smtp', 'tls_mode': 'unknown'})
    assert report.overall_status == 'UNKNOWN'
    assert report.overall_score is None
    assert report.unknown_count == 7


def test_observed_plaintext_fails_transport_checks_without_claiming_downgrade():
    report = ComplianceEvaluator.evaluate_session({'protocol': 'smtp', 'tls_mode': 'none'})
    assert report.overall_status == 'FAIL'
    assert report.overall_score == 0
    assert check(report, 'NIST-01').status == 'FAIL'
    assert check(report, 'PCI-02').status == 'FAIL'
    assert check(report, 'NIST-03').status == 'UNKNOWN'
    assert report.standards[STS].status == 'UNKNOWN'
    assert not any('stripped' in text.lower() or 'attack' in text.lower() for text in report.summary_findings)


def test_unrecognized_cipher_does_not_pass_from_absence_of_findings(modern_session):
    modern_session['handshake']['cipher_suite_negotiated'] = '0xFFFF'
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert check(report, 'PCI-02').status == 'UNKNOWN'
    assert report.standards[PCI].passed is False


def test_mta_policy_checks_not_applicable_to_non_smtp(modern_session):
    modern_session['protocol'] = ProtocolType.IMAP
    report = ComplianceEvaluator.evaluate_session(modern_session)
    assert report.standards[STS].status == 'NOT_APPLICABLE'
    assert report.standards[STS].not_applicable_count == 2
    assert report.standards[STS].passed is False
    assert report.standards[STS].score_percentage is None


def test_fleet_aggregation_preserves_unknown_counts_and_missing_scores(modern_session):
    fleet = evaluate_fleet_compliance([modern_session, {'protocol': 'smtp', 'tls_mode': 'unknown'}])
    assert fleet['total_sessions_audited'] == 2
    assert fleet['framework_scores'][NIST] == 50
    assert fleet['framework_scores'][PCI] == 50
    assert fleet['framework_scores'][STS] is None
    assert fleet['framework_unknown_counts'] == {NIST: 3, PCI: 2, STS: 4}
    assert fleet['unknown_count'] == 9
    assert fleet['overall_status'] == 'UNKNOWN'
    assert fleet['top_violations'] == []


def test_empty_fleet_is_not_assessed_instead_of_zero_compliance():
    fleet = evaluate_fleet_compliance([])
    assert fleet['overall_status'] == 'NOT_ASSESSED'
    assert fleet['overall_score'] is None
    assert fleet['framework_scores'] == {}


def test_compliance_api_endpoint(monkeypatch):
    """Verify GET /api/compliance/summary requires auth and returns report."""
    client = TestClient(app)

    # 401 without auth
    unauth_res = client.get("/api/compliance/summary")
    assert unauth_res.status_code == 401

    from secure_smtp.api.routers import compliance

    class ScopedSessions:
        def find(self, query):
            assert query == {"org_id": "org_pilot", "published": {"$ne": False}}
            return []

    monkeypatch.setattr(compliance, "get_sessions_col", lambda: ScopedSessions())
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    auth_res = client.get("/api/compliance/summary")
    assert auth_res.status_code == 200
    data = auth_res.json()
    assert "overall_status" in data
    assert "framework_scores" in data
