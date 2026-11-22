"""
Unit tests for Generative AI Security Copilot & Remediation Synthesizer.
"""

import pytest
from fastapi.testclient import TestClient

from secure_smtp.ai.copilot import (
    ask_copilot,
    generate_incident_briefing,
    generate_server_remediation,
)
from secure_smtp.api.auth import Principal, verify_api_key
from secure_smtp.api.main import app


@pytest.fixture(autouse=True)
def offline_templates(monkeypatch):
    # Unit tests must never send findings to an external model service.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SECURE_SMTP_GEMINI_KEY", raising=False)


@pytest.fixture
def mock_session():
    return {
        "id": 101,
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.20",
        "protocol": "SMTP",
        "tls_mode": "starttls",
    }


@pytest.fixture
def mock_findings():
    return [
        {
            "rule_id": "starttls-stripped",
            "severity": "critical",
            "message": "STARTTLS was advertised but never completed — possible downgrade/stripping attack",
            "recommendation": "Investigate for an on-path attacker; consider MTA-STS/DANE enforcement.",
        },
        {
            "rule_id": "deprecated-tls-version",
            "severity": "high",
            "message": "Deprecated TLS version negotiated: TLS1.0",
            "recommendation": "Disable TLS 1.0; require TLS 1.2 minimum, prefer TLS 1.3.",
        },
        {
            "rule_id": "weak-cipher",
            "severity": "high",
            "message": "Weak cipher suite negotiated: TLS_RSA_WITH_RC4_128_SHA",
            "recommendation": "Restrict server cipher list to AEAD ciphers.",
        },
    ]


def test_generate_postfix_remediation(mock_session, mock_findings):
    res = generate_server_remediation(mock_session, mock_findings, "postfix")
    assert res["server_type"] == "postfix"
    assert "/etc/postfix/main.cf" in res["filepath"]
    assert "smtpd_tls_protocols" in res["config_content"]
    assert "tls_high_cipherlist" in res["config_content"]
    assert len(res["commands"]) > 0
    assert "starttls-stripped" in res["addressed_findings"]
    assert "deprecated-tls-version" in res["addressed_findings"]
    assert res["resolved_findings"] == []
    assert res["generation_method"] == "rule_based_template"
    assert res["review_required"] is True


def test_generate_dovecot_remediation(mock_session, mock_findings):
    res = generate_server_remediation(mock_session, mock_findings, "dovecot")
    assert res["server_type"] == "dovecot"
    assert "ssl_min_protocol = TLSv1.2" in res["config_content"]
    assert "ssl_cipher_list" in res["config_content"]


def test_generate_exchange_remediation(mock_session, mock_findings):
    res = generate_server_remediation(mock_session, mock_findings, "exchange")
    assert res["server_type"] == "exchange"
    assert "SCHANNEL" in res["config_content"]
    assert "RequireTLS" in res["config_content"]


def test_generate_incident_briefing(mock_session, mock_findings):
    briefing = generate_incident_briefing(mock_session, mock_findings, risk_score=85.0)
    assert briefing["risk_level"] == "CRITICAL"
    assert "192.168.1.20" in briefing["content_markdown"]
    assert "STARTTLS" in briefing["content_markdown"]
    assert briefing["generation_method"] == "rule_based_template"
    assert "PCI-DSS v4.0" in briefing["content_markdown"]


def test_ask_copilot_questions(mock_session, mock_findings):
    # Test zero-downtime question
    q1 = ask_copilot(mock_session, mock_findings, "Will disabling TLS 1.0 cause downtime or break legacy clients?")
    assert "Zero-Downtime Migration" in q1["answer"]
    assert q1["generation_method"] == "rule_based_template"
    assert "not external AI" in q1["engine"]

    # Test threat question
    q2 = ask_copilot(mock_session, mock_findings, "What is the threat if this is left unpatched?")
    assert "STARTTLS" in q2["answer"]
    assert q2["generation_method"] == "rule_based_template"

    # Test quantum question
    q3 = ask_copilot(mock_session, mock_findings, "Is this vulnerable to quantum harvest attacks?")
    assert "Post-Quantum Cryptography" in q3["answer"]


def test_copilot_api_endpoints(monkeypatch, mock_session, mock_findings):
    client = TestClient(app)

    # Mock database session retrieval
    fake_session_doc = {
        "id": 8,
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.20",
        "protocol": "SMTP",
        "tls_mode": "starttls",
        "findings": mock_findings,
        "risk_score": {"score_0_100": 78.5, "tier": "critical"},
    }

    from secure_smtp.api import main

    class FakeCollection:
        def find_one(self, query):
            assert query.get("org_id") == "org_pilot"
            if query.get("id") == 8:
                return fake_session_doc
            return None

    monkeypatch.setattr(main, "get_sessions_col", lambda: FakeCollection())

    assert client.post("/api/sessions/8/copilot/ask", json={"query": "Explain"}).status_code == 401
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    headers = {}

    # Test remediate endpoint
    r1 = client.post("/api/sessions/8/copilot/remediate", json={"server_type": "postfix"}, headers=headers)
    assert r1.status_code == 200
    assert "main.cf" in r1.json()["filepath"]

    # Test briefing endpoint
    r2 = client.post("/api/sessions/8/copilot/briefing", headers=headers)
    assert r2.status_code == 200
    assert "Briefing" in r2.json()["title"]

    # Test ask endpoint
    r3 = client.post("/api/sessions/8/copilot/ask", json={"query": "Explain the threat"}, headers=headers)
    assert r3.status_code == 200
    assert "answer" in r3.json()


def test_empty_fleet_does_not_invent_ai_scores_or_session_context(monkeypatch):
    from secure_smtp.api import main

    class EmptyCollection:
        def count_documents(self, query):
            assert query.get("org_id") == "org_pilot"
            return 0

        def find_one(self, query, **kwargs):
            assert query.get("org_id") == "org_pilot"
            return None

    monkeypatch.setattr(main, "get_sessions_col", lambda: EmptyCollection())
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    client = TestClient(app)
    response = client.get("/api/ai/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["engine"] == "Rule-based templates"
    assert data["explainable_ai"]["primary_features"] == []
    assert data["post_quantum_readiness"]["pqc_score"] is None
    assert data["post_quantum_readiness"]["risk_status"] == "Not assessed"
    assert data["isolation_forest"]["conformity_rate"] is None
    assert client.post("/api/ai/copilot/ask", json={"query": "Explain"}).status_code == 404


def test_inaccessible_explicit_session_does_not_fall_back_to_another_session(monkeypatch):
    from secure_smtp.api import main
    calls = []

    class ScopedCollection:
        def find_one(self, query, **kwargs):
            calls.append(query)
            assert query == {"id": 123, "org_id": "org_pilot", "published": {"$ne": False}}
            return None

    monkeypatch.setattr(main, "get_sessions_col", lambda: ScopedCollection())
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    response = TestClient(app).post("/api/ai/copilot/ask", json={"query": "Explain", "session_id": 123})
    assert response.status_code == 404
    assert len(calls) == 1
