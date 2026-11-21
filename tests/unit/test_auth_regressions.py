"""Behavioral regressions for the authentication bypass and report isolation."""

import hashlib
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from secure_smtp.api import sessions_auth as auth
from secure_smtp.api.main import app
from secure_smtp.api.ratelimit import get_rate_limiter
from secure_smtp.config import get_settings

PASSWORD = "Test-only-password-29482!"
ORIGIN = "http://localhost:5173"


@pytest.fixture
def local(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "local_admin_email", "operator@example.test")
    monkeypatch.setattr(settings, "local_password_hash", auth.hash_password(PASSWORD))
    monkeypatch.setattr(settings, "clerk_issuer", "")
    monkeypatch.setattr(settings, "environment", "testing")
    monkeypatch.setattr(settings, "cors_origins", [ORIGIN])
    auth._sessions.clear()
    auth._tickets.clear()
    get_rate_limiter().reset()
    yield TestClient(app)
    auth._sessions.clear()
    auth._tickets.clear()
    get_rate_limiter().reset()


def sign_in(client, password=PASSWORD, email="operator@example.test"):
    return client.post(
        "/api/auth/login", json={"email": email, "password": password}, headers={"Origin": ORIGIN}
    )


def test_wrong_password_and_unknown_user_cannot_login(local):
    assert sign_in(local, "anything").status_code == 401
    assert sign_in(local, email="unknown@example.test").status_code == 401
    assert local.get("/api/auth/me").status_code == 401


def test_verified_login_cookie_logout_and_revocation(local):
    response = sign_in(local)
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    cookie = local.cookies.get(auth.COOKIE)
    assert local.get("/api/auth/me").json()["email"] == "operator@example.test"
    assert local.post("/api/auth/logout", headers={"Origin": ORIGIN}).status_code == 200
    local.cookies.set(auth.COOKIE, cookie)
    assert local.get("/api/auth/me").status_code == 401


def test_fake_cookie_expired_session_and_csrf_rejected(local):
    local.cookies.set(auth.COOKIE, '{"email":"admin","role":"admin"}')
    assert local.get("/api/auth/me").status_code == 401
    local.cookies.clear()
    sign_in(local)
    assert (
        local.post("/api/auth/logout", headers={"Origin": "https://evil.test"}).status_code == 403
    )
    assert local.post("/api/auth/ws-ticket").status_code == 403
    cookie = local.cookies.get(auth.COOKIE)
    auth._sessions[hashlib.sha256(cookie.encode()).hexdigest()] = (time.time() - 1, "operator")
    assert local.get("/api/auth/me").status_code == 401


def test_unconfigured_login_fails_closed(local, monkeypatch):
    monkeypatch.setattr(get_settings(), "local_password_hash", "")
    assert sign_in(local).status_code == 503


def test_rate_limit_cannot_be_bypassed_with_forwarded_header(local):
    for i in range(5):
        response = local.post(
            "/api/auth/login",
            json={"email": "a@b.test", "password": "bad"},
            headers={"Origin": ORIGIN, "X-Forwarded-For": f"10.1.1.{i}"},
        )
        assert response.status_code == 401
    assert sign_in(local).status_code == 429


def test_websocket_requires_one_use_ticket(local):
    with pytest.raises(WebSocketDisconnect):
        with local.websocket_connect("/ws/live"):
            pass
    sign_in(local)
    ticket = local.post("/api/auth/ws-ticket", headers={"Origin": ORIGIN}).json()["ticket"]
    with local.websocket_connect("/ws/live?token=" + ticket, headers={"Origin": ORIGIN}) as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"
    with pytest.raises(WebSocketDisconnect):
        with local.websocket_connect("/ws/live?token=" + ticket):
            pass


def test_clerk_verifies_signature_expiry_issuer_origin_and_org(local, monkeypatch):
    settings = get_settings()
    issuer = "https://example.clerk.accounts.dev"
    monkeypatch.setattr(settings, "clerk_issuer", issuer)
    monkeypatch.setattr(settings, "clerk_org_id", "org_pilot")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        auth,
        "jwks_client",
        lambda _: SimpleNamespace(
            get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key.public_key())
        ),
    )
    now = int(time.time())
    claims = dict(
        iss=issuer,
        sub="user_verified",
        iat=now,
        nbf=now - 1,
        exp=now + 60,
        azp=ORIGIN,
        o={"id": "org_pilot"},
    )

    def call(payload, signer=key):
        token = jwt.encode(payload, signer, algorithm="RS256")
        return local.get("/api/auth/me", headers={"Authorization": "Bearer " + token})

    assert call(claims).status_code == 200
    assert call(claims, other).status_code == 401
    for changes in [
        {"exp": now - 60},
        {"iss": "https://evil.test"},
        {"azp": "https://evil.test"},
        {"o": {"id": "org_other"}},
        {"sts": "pending"},
    ]:
        assert call({**claims, **changes}).status_code in (401, 403)
    assert (
        local.get("/api/auth/me", headers={"Authorization": "Bearer forged.jwt.token"}).status_code
        == 401
    )


def test_report_scoped_to_job_and_host_totals(tmp_path, monkeypatch):
    from secure_smtp.api import pipeline
    from secure_smtp.reporting import html_export, json_export, pdf_export

    selected = {
        "id": 1,
        "job_id": "job_a",
        "host_id": 7,
        "findings": [],
        "risk_score": {"score_0_100": 25, "tier": "medium"},
    }
    sessions = MagicMock()
    sessions.find.side_effect = lambda query, projection: (
        [selected] if query == {"job_id": "job_a"} else pytest.fail("unscoped query")
    )
    hosts = MagicMock()
    hosts.find.return_value = [{"id": 7, "session_count": 999, "aggregate_risk_score": 100}]
    monkeypatch.setattr(pipeline, "get_sessions_col", lambda: sessions)
    monkeypatch.setattr(pipeline, "get_hosts_col", lambda: hosts)
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    captured = []
    monkeypatch.setattr(
        json_export, "generate_json_report", lambda data, path: captured.append(data)
    )
    monkeypatch.setattr(html_export, "generate_html_report", lambda *args: None)
    monkeypatch.setattr(pdf_export, "generate_pdf_report", lambda *args, **kwargs: None)
    pipeline.generate_job_reports("job_a")
    assert captured[0]["summary"]["total_sessions"] == 1
    assert captured[0]["hosts"][0]["session_count"] == 1
    assert captured[0]["hosts"][0]["aggregate_risk_score"] == 25
    hosts.find.assert_called_once_with({"id": {"$in": [7]}}, {"_id": 0})


def test_html_report_escapes_untrusted_data(tmp_path):
    from secure_smtp.reporting.html_export import generate_html_report

    data = {
        "title": "report",
        "summary": {},
        "hosts": [
            {
                "ip_or_hostname": "<script>alert(1)</script>",
                "aggregate_risk_score": 0,
                "session_count": 1,
            }
        ],
        "sessions": [],
    }
    path = tmp_path / "report.html"
    generate_html_report(data, str(path))
    html = path.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_production_cookie_and_lab_target_restrictions(local, monkeypatch):
    monkeypatch.setattr(get_settings(), "environment", "production")
    assert "Secure" in sign_in(local).headers["set-cookie"].split("; ")
    from secure_smtp.api.routers.live import CustomMailDispatchRequest

    for host in [
        "169.254.169.254",
        "2130706433",
        "evil.example",
        "::ffff:169.254.169.254",
        "8.8.8.8",
    ]:
        with pytest.raises(ValueError):
            CustomMailDispatchRequest(server_ip=host)


def test_alerts_use_configured_threshold_and_lowercase_findings(local, monkeypatch):
    from secure_smtp.alerts.engine import AlertEngine

    settings = get_settings()
    monkeypatch.setattr(settings, "alert_min_severity", "CRITICAL")
    monkeypatch.setattr(settings, "alert_risk_threshold", 95)
    engine = AlertEngine(webhook_url="http://localhost/webhook", enabled=True)
    assert not engine.should_alert([{"severity": "high"}], 80)
    payload = engine.build_payload(
        1, "a", "b", "smtp", 99, [{"severity": "critical", "rule_id": "no-tls"}]
    )
    assert payload["security"]["critical_findings"] == ["no-tls"]


def test_certificate_matching_issuer_name_does_not_prove_signature():
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    from secure_smtp.tls.cert_parser import parse_certificate_chain

    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer")])
    now = datetime.now(UTC)

    def cert(subject, public, signer):
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(name)
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .sign(signer, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

    leaf = cert(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail")]), wrong.public_key(), wrong
    )
    root = cert(name, good.public_key(), good)
    assert parse_certificate_chain([leaf, root])[0].chain_valid is False


def test_malicious_tcp_sequence_gap_cannot_allocate_gigabytes():
    from secure_smtp.ingest.pcap_reader import RawPacket
    from secure_smtp.ingest.tcp_stream import _reassemble_direction

    def packet(seq):
        return RawPacket(
            src_ip="a",
            dst_ip="b",
            src_port=1,
            dst_port=25,
            seq=seq,
            ack=0,
            flags="A",
            payload=b"x",
            timestamp=0,
        )

    with pytest.raises(ValueError, match="16 MiB"):
        _reassemble_direction([packet(1), packet(2**32 - 1)])


def test_ipv6_mail_capture_is_analyzed(tmp_path):
    from scapy.all import TCP, IPv6, Raw, wrpcap

    from secure_smtp.ingest.pcap_reader import read_pcap

    path = tmp_path / "ipv6.pcap"
    wrpcap(
        str(path), [IPv6(src="::1", dst="::2") / TCP(sport=45000, dport=25) / Raw(b"EHLO test\r\n")]
    )
    streams = read_pcap(path)
    assert len(streams) == 1
    assert streams[0].packets[0].src_ip == "::1"


def test_real_webhook_delivery_to_local_receiver():
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from secure_smtp.alerts.engine import AlertEngine

    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((json.loads(body), self.headers.get("X-SecureSMTP-Signature")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        engine = AlertEngine(
            webhook_url=f"http://127.0.0.1:{server.server_port}/alerts",
            secret="test-secret",
            enabled=True,
        )
        assert engine.send(
            1, "127.0.0.1", "127.0.0.2", "smtp", 99, [{"severity": "critical", "rule_id": "no-tls"}]
        )
        assert received[0][0]["security"]["critical_findings"] == ["no-tls"]
        assert received[0][1].startswith("sha256=")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
