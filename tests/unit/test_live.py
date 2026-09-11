"""
Unit tests for Live Mail Lab & WebSocket Streaming.
"""

import asyncio
import pytest
from fastapi.testclient import TestClient

from secure_smtp.api.main import app
from secure_smtp.live.generator import simulate_live_session
from secure_smtp.live.mail_server import LiveMailLab, ensure_test_certificates


def test_ensure_test_certificates():
    c1, k1, c2, k2 = ensure_test_certificates()
    assert c1.exists()
    assert k1.exists()
    assert c2.exists()
    assert k2.exists()


@pytest.mark.asyncio
async def test_live_mail_lab_lifecycle():
    lab = LiveMailLab(host="127.0.0.1")
    # Test starting and stopping
    ports = await lab.start()
    assert "plaintext" in ports
    assert "tls_modern" in ports
    assert "vulnerable" in ports
    assert "stripping" in ports
    assert lab.is_running is True

    # Test connecting to live plaintext port and sending standard SMTP dialogue
    reader, writer = await asyncio.open_connection("127.0.0.1", 2525)
    banner = await reader.readline()
    assert b"220" in banner
    writer.write(b"EHLO client.test\r\nQUIT\r\n")
    await writer.drain()
    resp = await reader.read()
    assert b"221" in resp
    writer.close()
    await writer.wait_closed()

    # Small delay for async recording
    await asyncio.sleep(0.1)

    await lab.stop()
    assert lab.is_running is False


@pytest.mark.asyncio
async def test_simulate_live_session_stripped():
    res = await simulate_live_session("starttls_stripped")
    assert res["event"] == "NEW_SESSION"
    assert "session_id" in res
    assert res["protocol"] == "SMTP"
    assert res["dst_port"] in (25, 2528)


def test_live_api_endpoints():
    client = TestClient(app)
    headers = {"X-API-Key": "securesmtp_live_secret_key"}

    # Test status endpoint
    r1 = client.get("/api/live/status", headers=headers)
    assert r1.status_code == 200
    data = r1.json()
    assert "status" in data
    assert "ports" in data

    # Test simulate endpoint
    r2 = client.post("/api/live/simulate/tls13_good", headers=headers)
    assert r2.status_code == 200
    sim_data = r2.json()
    assert sim_data["event"] == "NEW_SESSION"
    assert "session_id" in sim_data


def test_websocket_connection():
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as websocket:
        websocket.send_text("ping")
        resp = websocket.receive_text()
        assert resp == "pong"
