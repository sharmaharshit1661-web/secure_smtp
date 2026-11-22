"""
Unit tests for Live Mail Lab & WebSocket Streaming.
"""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from secure_smtp.api.auth import Principal, verify_api_key
from secure_smtp.api.broker import ConnectionManager
from secure_smtp.api.main import app
from secure_smtp.live.generator import simulate_live_session
from secure_smtp.live.mail_server import LiveMailLab, ensure_test_certificates


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", ["_handle_modern_tls", "_handle_vulnerable_tls"])
@pytest.mark.parametrize("failure", ["rejected", "closed"])
async def test_lab_failed_tls_never_records_completed_handshake(monkeypatch, tmp_path, handler, failure):
    from unittest.mock import AsyncMock, Mock

    from secure_smtp.live import mail_server

    monkeypatch.setattr(mail_server, "ensure_test_certificates", lambda: (tmp_path / "cert",) * 4)
    monkeypatch.setattr(mail_server.ssl, "create_default_context", lambda *a: Mock())
    start_tls = AsyncMock(side_effect=ConnectionError("Handshake rejected")) if failure == "rejected" else AsyncMock(return_value=None)
    monkeypatch.setattr(asyncio.get_running_loop(), "start_tls", start_tls)
    reader = Mock(readline=AsyncMock(side_effect=[b"STARTTLS\r\n", b""]))
    writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
    writer.get_extra_info.side_effect = lambda key: ("127.0.0.1", 2527)
    lab = LiveMailLab()
    lab._record_and_broadcast = AsyncMock()
    await getattr(lab, handler)(reader, writer)
    evidence = lab._record_and_broadcast.call_args.kwargs
    assert evidence["starttls_completed"] is False
    assert evidence["cert_path"] is None
    assert evidence["tls_version"] == evidence["cipher"] == ""


@pytest.mark.parametrize("version,cipher", [("", ""), ("TLS1.3", "TLS_AES_256_GCM_SHA384")])
def test_lab_socket_metadata_does_not_invent_fingerprints_or_forward_secrecy(version, cipher):
    from secure_smtp.live.mail_server import _socket_handshake

    handshake = _socket_handshake(1, version, cipher)
    assert handshake.tls_version_negotiated == version
    assert handshake.cipher_suite_negotiated == cipher
    assert handshake.ja3 == handshake.ja3s == handshake.ja4 == handshake.ja4s == ""
    assert handshake.forward_secrecy is None
    assert handshake.key_exchange_type.value == "unknown"
    assert handshake.visibility_limited


def test_ensure_test_certificates(monkeypatch, tmp_path):
    from secure_smtp.live import mail_server
    monkeypatch.setattr(mail_server, "CERTS_DIR", tmp_path)
    c1, k1, c2, k2 = ensure_test_certificates()
    assert c1.exists()
    assert k1.exists()
    assert c2.exists()
    assert k2.exists()


@pytest.fixture
def isolated_live_db(monkeypatch):
    import uuid

    from secure_smtp.config import get_settings
    from secure_smtp.db import mongodb
    try:
        client = mongodb.get_mongo_client()
        client.admin.command("ping")
    except Exception:
        pytest.skip("MongoDB service not available for live lab integration")

    test_db = f"test_live_isolated_{uuid.uuid4().hex[:8]}"
    monkeypatch.setenv("SECURE_SMTP_PILOT_ORG_ID", "org_pilot")
    monkeypatch.setenv("SECURE_SMTP_MONGO_DB", test_db)
    monkeypatch.setattr(mongodb, "DATABASE_NAME", test_db)
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    mongodb.init_db_indexes()
    yield test_db
    try:
        client.drop_database(test_db)
    except Exception:
        pass
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_live_mail_lab_lifecycle(isolated_live_db):
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
async def test_simulate_live_session_stripped(isolated_live_db):
    res = await simulate_live_session("starttls_stripped")
    assert res["event"] == "NEW_SESSION"
    assert "session_id" in res
    assert res["protocol"] == "SMTP"
    assert res["dst_port"] in (25, 2528)


def test_live_status_requires_identity(monkeypatch):
    from secure_smtp.live import mail_server
    monkeypatch.setattr(mail_server, "get_live_lab", lambda: SimpleNamespace(is_running=False))
    monkeypatch.setattr(mail_server, "get_local_ip", lambda: "127.0.0.1")
    client = TestClient(app)
    assert client.get("/api/live/status").status_code == 401
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    response = client.get("/api/live/status")
    assert response.status_code == 200
    assert response.json()["is_running"] is False
    assert "ports" in response.json()


@pytest.mark.parametrize("path", ["start-lab", "stop-lab", "simulate/tls13_good", "clear-history", "dispatch-custom"])
def test_analyst_cannot_execute_lab_or_deletion_controls(monkeypatch, path):
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_analyst", "org_pilot", "member", 4102444800))
    assert TestClient(app).post(f"/api/live/{path}", json={}).status_code == 403


def test_admin_cannot_enable_deployment_disabled_lab(monkeypatch):
    from secure_smtp.api import auth
    monkeypatch.setattr(auth, "get_settings", lambda: SimpleNamespace(enable_live_lab=False))
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_admin", "org_pilot", "admin", 4102444800))
    client = TestClient(app)
    for path in ["start-lab", "stop-lab", "simulate/tls13_good", "dispatch-custom"]:
        assert client.post(f"/api/live/{path}", json={}).status_code == 403


@pytest.mark.parametrize("host,port", [("169.254.169.254", 80), ("127.0.0.1", 27017), ("mail.external.test", 25)])
def test_dispatch_rejects_arbitrary_network_destinations(monkeypatch, host, port):
    from secure_smtp.api import auth
    monkeypatch.setattr(auth, "get_settings", lambda: SimpleNamespace(enable_live_lab=True))
    monkeypatch.setitem(app.dependency_overrides, verify_api_key,
                        lambda: Principal("user_admin", "org_pilot", "admin", 4102444800))
    response = TestClient(app).post("/api/live/dispatch-custom", json={"server_ip": host, "port": port})
    assert response.status_code == 403


@pytest.fixture
def websocket_context(monkeypatch):
    from secure_smtp.api.routers import live
    manager = ConnectionManager()
    principal = Principal("user_analyst", "org_pilot", "member", 4102444800)
    monkeypatch.setattr(live, "get_settings", lambda: SimpleNamespace(clerk_authorized_parties=["https://pilot.example.test"]))
    monkeypatch.setattr(live, "get_connection_manager", lambda: manager)

    def verify(token):
        if token != "valid-test-session":
            raise HTTPException(401, "Invalid session")
        return principal

    monkeypatch.setattr(live, "verify_token", verify)
    return manager


def test_websocket_authenticates_before_registering_and_handles_ping(websocket_context):
    client = TestClient(app)
    with client.websocket_connect("/ws/live", headers={"Origin": "https://pilot.example.test"}) as websocket:
        assert not websocket_context.active_connections
        websocket.send_json({"token": "valid-test-session"})
        assert websocket.receive_json() == {"event": "AUTHENTICATED"}
        assert len(websocket_context.active_connections) == 1
        websocket.send_text("ping")
        assert websocket.receive_text() == "pong"
    assert not websocket_context.active_connections


def test_offline_websocket_uses_local_origin_without_clerk_configuration(websocket_context, monkeypatch):
    from secure_smtp.api.routers import live

    monkeypatch.setattr(live, "get_settings", lambda: SimpleNamespace(
        auth_provider="keycloak", cors_origins=["https://smtp.internal"],
        clerk_authorized_parties=[],
    ))
    with TestClient(app).websocket_connect("/ws/live", headers={"Origin": "https://smtp.internal"}) as socket:
        socket.send_json({"token": "valid-test-session"})
        assert socket.receive_json() == {"event": "AUTHENTICATED"}
        socket.send_text("ping")
        assert socket.receive_text() == "pong"
    with pytest.raises(WebSocketDisconnect) as rejected:
        with TestClient(app).websocket_connect("/ws/live", headers={"Origin": "https://foreign.test"}):
            pytest.fail("Foreign origin was accepted")
    assert rejected.value.code == 4403


@pytest.mark.asyncio
async def test_broker_failed_expired_connection_does_not_block_healthy_subscriber():
    from unittest.mock import AsyncMock, Mock

    manager = ConnectionManager()
    expired = Mock(close=AsyncMock(side_effect=RuntimeError("Already closed")))
    healthy = Mock(send_json=AsyncMock())
    await manager.connect(expired, Principal("expired", "org_a", "member", 1), accepted=True)
    await manager.connect(healthy, Principal("current", "org_a", "member", 4102444800), accepted=True)
    await manager.broadcast({"event": "NEW_SESSION", "org_id": "org_a"})
    assert expired not in manager.active_connections
    healthy.send_json.assert_awaited_once()


@pytest.mark.parametrize("origin", [None, "https://untrusted.example.test"])
def test_websocket_rejects_missing_or_untrusted_origin(websocket_context, origin):
    with pytest.raises(WebSocketDisconnect) as rejected:
        with TestClient(app).websocket_connect("/ws/live", headers={"Origin": origin} if origin else {}):
            pytest.fail("Untrusted origin was accepted")
    assert rejected.value.code == 4403
    assert not websocket_context.active_connections


@pytest.mark.parametrize("message", ["ping", "{}", "[]", "null", '{"token":"invalid"}', "x" * 16401])
def test_websocket_invalid_first_message_never_registers(websocket_context, message):
    with TestClient(app).websocket_connect("/ws/live", headers={"Origin": "https://pilot.example.test"}) as websocket:
        websocket.send_text(message)
        with pytest.raises(WebSocketDisconnect) as rejected:
            websocket.receive_text()
        assert rejected.value.code == 4401
    assert not websocket_context.active_connections


@pytest.mark.asyncio
async def test_broker_does_not_broadcast_to_other_org_or_unowned_records():
    class FakeSocket:
        def __init__(self):
            self.messages = []

        async def send_json(self, message):
            self.messages.append(message)

    manager = ConnectionManager()
    a, b = FakeSocket(), FakeSocket()
    await manager.connect(a, Principal("a", "org_a", "member", 4102444800), accepted=True)
    await manager.connect(b, Principal("b", "org_b", "member", 4102444800), accepted=True)
    await manager.broadcast({"event": "NEW_SESSION", "org_id": "org_a"})
    await manager.broadcast({"event": "NEW_SESSION"})
    assert a.messages == [{"event": "NEW_SESSION", "org_id": "org_a"}]
    assert b.messages == []
