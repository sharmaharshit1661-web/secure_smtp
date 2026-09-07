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
from secure_smtp.api.main import app


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
    assert "starttls-stripped" in res["resolved_findings"]
    assert "deprecated-tls-version" in res["resolved_findings"]


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
    assert "STARTTLS Stripping Attack" in briefing["content_markdown"]
    assert "PCI-DSS v4.0" in briefing["content_markdown"]


def test_ask_copilot_questions(mock_session, mock_findings):
    # Test zero-downtime question
    q1 = ask_copilot(mock_session, mock_findings, "Will disabling TLS 1.0 cause downtime or break legacy clients?")
    assert "Zero-Downtime Migration" in q1["answer"]
    assert "99.7%" in q1["answer"]

    # Test threat question
    q2 = ask_copilot(mock_session, mock_findings, "What is the threat if this is left unpatched?")
    assert "STARTTLS Stripping Attack" in q2["answer"]

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
            if query.get("id") == 8:
                return fake_session_doc
            return None

    monkeypatch.setattr(main, "get_sessions_col", lambda: FakeCollection())

    headers = {"X-API-Key": "securesmtp_live_secret_key"}

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
