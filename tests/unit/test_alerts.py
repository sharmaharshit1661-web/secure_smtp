"""
Unit tests for the real-time alerting and webhook notification engine.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from secure_smtp.alerts.engine import AlertEngine


def test_should_alert_disabled_by_default():
    """Alerts should not fire if no webhook URL is configured."""
    engine = AlertEngine(webhook_url=None, enabled=False)
    findings = [{"severity": "CRITICAL", "rule_id": "SEC-008"}]
    assert engine.should_alert(findings, risk_score=95.0) is False


def test_should_alert_on_high_risk_score():
    """Alerts fire if risk score exceeds threshold even with no findings."""
    engine = AlertEngine(
        webhook_url="https://hooks.example.com/alerts",
        risk_threshold=70.0,
        enabled=True,
    )
    assert engine.should_alert([], risk_score=85.0) is True
    assert engine.should_alert([], risk_score=60.0) is False


def test_should_alert_on_severity_threshold():
    """Alerts fire when a finding meets or exceeds min_severity."""
    engine = AlertEngine(
        webhook_url="https://hooks.example.com/alerts",
        min_severity="HIGH",
        risk_threshold=90.0,
        enabled=True,
    )
    # LOW severity does not trigger
    assert engine.should_alert([{"severity": "LOW"}], risk_score=20.0) is False
    # HIGH triggers
    assert engine.should_alert([{"severity": "HIGH"}], risk_score=20.0) is True
    # CRITICAL triggers
    assert engine.should_alert([{"severity": "CRITICAL"}], risk_score=20.0) is True


def test_build_payload_standard_and_slack():
    """Verify standard payload and Slack-specific payload generation."""
    engine_std = AlertEngine(webhook_url="https://siem.corp.internal/webhook", enabled=True)
    payload_std = engine_std.build_payload(
        session_id=42,
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        protocol="SMTP",
        risk_score=88.5,
        findings=[{"rule_id": "SEC-008", "severity": "CRITICAL", "title": "STARTTLS Stripped"}],
    )

    assert payload_std["event"] == "cryptographic_posture_alert"
    assert payload_std["session_id"] == 42
    assert payload_std["traffic"]["server_ip"] == "10.0.0.2"
    assert payload_std["security"]["risk_tier"] == "CRITICAL"

    # Slack format
    engine_slack = AlertEngine(webhook_url="https://hooks.slack.com/services/T00/B00/X00", enabled=True)
    payload_slack = engine_slack.build_payload(
        session_id=42,
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        protocol="SMTP",
        risk_score=88.5,
        findings=[{"rule_id": "SEC-008", "severity": "CRITICAL", "title": "STARTTLS Stripped"}],
    )
    assert "text" in payload_slack
    assert "attachments" in payload_slack


def test_hmac_signature_generation():
    """Verify HMAC-SHA256 signature when secret is provided."""
    secret = "my_shared_webhook_secret_key"
    engine = AlertEngine(
        webhook_url="https://hooks.example.com/alerts",
        secret=secret,
        enabled=True,
    )
    body = b'{"hello": "world"}'
    sig = engine.sign_payload(body)
    assert sig.startswith("sha256=")
    assert len(sig) == 7 + 64  # sha256= + 64 hex chars


def test_send_webhook_dispatch_mock():
    """Verify HTTP dispatch with headers and payload."""
    engine = AlertEngine(
        webhook_url="https://webhook.site/test-uuid",
        secret="secret123",
        enabled=True,
        min_severity="HIGH",
    )

    mock_response = MagicMock()
    mock_response.is_success = True
    mock_response.status_code = 200

    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        sent = engine.send(
            session_id=1,
            client_ip="192.168.1.5",
            server_ip="192.168.1.10",
            protocol="SMTP",
            risk_score=85.0,
            findings=[{"severity": "CRITICAL", "title": "STARTTLS Stripped"}],
        )

        assert sent is True
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "https://webhook.site/test-uuid"
        assert kwargs["headers"]["Content-Type"] == "application/json"
        assert "X-SecureSMTP-Signature" in kwargs["headers"]
