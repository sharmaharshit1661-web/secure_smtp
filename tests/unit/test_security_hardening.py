"""
Unit tests for enterprise security hardening layers:
- Security response headers & X-Request-ID tracing
- Rate limiting middleware & HTTP 429 Retry-After quotas
- PCAP upload streaming safety & magic byte validation
- Production secret fail-fast validation
- WebSocket authentication verification
"""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from secure_smtp.api.auth import DEFAULT_DEV_API_KEY
from secure_smtp.api.main import app, lifespan
from secure_smtp.api.ratelimit import get_rate_limiter
from secure_smtp.config import Settings, get_settings

client = TestClient(app)


def test_security_headers_present():
    """Verify enterprise defensive HTTP security headers on all responses."""
    response = client.get("/api/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("Permissions-Policy", "")
    assert "X-Request-ID" in headers


def test_request_id_tracing_propagation():
    """Verify client-supplied X-Request-ID is preserved and echoed in telemetry."""
    custom_trace_id = "test-security-audit-uuid-9999"
    response = client.get("/api/health", headers={"X-Request-ID": custom_trace_id})
    assert response.status_code == 200
    assert response.headers.get("X-Request-ID") == custom_trace_id


@pytest.mark.asyncio
async def test_production_secret_fail_fast():
    """App must refuse to start in production if insecure default development key is retained."""
    prod_insecure_settings = Settings(
        environment="production",
        auth_required=True,
        api_key=DEFAULT_DEV_API_KEY,
    )

    with patch("secure_smtp.api.main.get_settings", return_value=prod_insecure_settings):
        with pytest.raises(RuntimeError, match="Refusing to start in production mode"):
            async with lifespan(app):
                pass


def test_pcap_upload_invalid_magic_bytes_rejected():
    """Uploading non-PCAP content with a .pcap extension is rejected via magic byte inspection."""
    fake_pcap_payload = b"NOT_A_REAL_PCAP_BINARY_DATA_CORRUPT"
    files = {
        "file": ("malicious_payload.pcap", io.BytesIO(fake_pcap_payload), "application/vnd.tcpdump.pcap"),
    }
    response = client.post(
        "/api/analyze",
        headers={"X-API-Key": DEFAULT_DEV_API_KEY},
        files=files,
    )
    assert response.status_code == 400
    assert "magic signature" in response.json()["detail"].lower()


def test_pcap_upload_valid_magic_bytes_accepted():
    """Uploading valid PCAP magic bytes (0xa1b2c3d4) passes pre-flight checks."""
    valid_pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    files = {
        "file": ("valid_sample.pcap", io.BytesIO(valid_pcap_header), "application/vnd.tcpdump.pcap"),
    }
    response = client.post(
        "/api/analyze",
        headers={"X-API-Key": DEFAULT_DEV_API_KEY},
        files=files,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "queued"
    assert "job_id" in data


def test_rate_limiting_enforcement():
    """Rapid requests exceeding endpoint quota trigger HTTP 429 Too Many Requests."""
    limiter = get_rate_limiter()
    limiter.reset()

    # Hit clear-history endpoint which has a strict quota of 5 per minute
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}

    status_codes = []
    for _ in range(8):
        resp = client.post("/api/live/clear-history", headers=headers)
        status_codes.append(resp.status_code)

    assert 200 in status_codes
    assert 429 in status_codes
    limiter.reset()


def test_websocket_auth_rejection_with_invalid_token():
    """Connecting to WebSocket with an invalid token causes immediate connection drop."""
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/live?token=invalid_forged_key"):
            pass


def test_websocket_auth_acceptance_with_valid_token():
    """Connecting to WebSocket with the valid API key token succeeds."""
    with client.websocket_connect("/ws/live", headers={"X-API-Key": DEFAULT_DEV_API_KEY}) as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"


def test_path_traversal_on_reports_endpoint_blocked():
    """Attempted path traversal on report downloads is blocked with HTTP 400 or 403."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    traversal_ids = ["..%2F..%2Fetc%2Fpasswd", "../../etc/passwd", "../report"]
    for tid in traversal_ids:
        resp = client.get(f"/api/reports/{tid}.json", headers=headers)
        assert resp.status_code in (400, 403, 404)


def test_smtp_header_crlf_injection_blocked():
    """CRLF characters in sender/recipient are rejected with HTTP 422 to prevent SMTP command injection."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    payload = {
        "server_ip": "127.0.0.1",
        "port": 2525,
        "scenario": "plaintext",
        "sender": "alice@local\r\nRCPT TO:<injected@evil.com>",
        "recipient": "bob@local",
        "subject": "Harmless",
    }
    resp = client.post("/api/live/dispatch-custom", json=payload, headers=headers)
    assert resp.status_code == 422
    assert "CRLF characters" in str(resp.json())


def test_ssrf_metadata_blocked():
    """Cloud metadata endpoints (169.254.169.254) are rejected with HTTP 422 to prevent SSRF attacks."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    payload = {
        "server_ip": "169.254.169.254",
        "port": 2525,
        "scenario": "plaintext",
        "sender": "alice@local",
        "recipient": "bob@local",
        "subject": "Test",
    }
    resp = client.post("/api/live/dispatch-custom", json=payload, headers=headers)
    assert resp.status_code == 422
    assert resp.json()["detail"][0]["loc"] == ["body", "server_ip"]


def test_ssrf_port_scanning_blocked():
    """Non-SMTP ports (e.g., SSH on port 22, Redis on 6379) are rejected to prevent internal port scanning."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    payload = {
        "server_ip": "127.0.0.1",
        "port": 22,
        "scenario": "plaintext",
        "sender": "alice@local",
        "recipient": "bob@local",
        "subject": "Test",
    }
    resp = client.post("/api/live/dispatch-custom", json=payload, headers=headers)
    assert resp.status_code == 422
    assert "not permitted" in str(resp.json())


def test_session_pagination_query_bounds():
    """Session limit parameter enforces bounds between 1 and 1000."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    resp_over = client.get("/api/sessions?limit=5000", headers=headers)
    assert resp_over.status_code == 422

    resp_under = client.get("/api/sessions?limit=0", headers=headers)
    assert resp_under.status_code == 422


def test_copilot_prompt_length_bounds():
    """Excessively long copilot queries are rejected to prevent prompt bombing."""
    headers = {"X-API-Key": DEFAULT_DEV_API_KEY}
    giant_query = "A" * 3000
    resp = client.post("/api/ai/copilot/ask", json={"query": giant_query}, headers=headers)
    assert resp.status_code == 422

