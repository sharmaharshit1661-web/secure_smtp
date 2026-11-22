"""
Unit tests for CORS security middleware configuration.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from secure_smtp.api.main import app
from secure_smtp.config import Settings


def test_cors_preflight_allowed_origin():
    """Verify that trusted local dev origin gets valid CORS headers."""
    client = TestClient(app)
    response = client.options(
        "/api/hosts",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"
    assert "GET" in response.headers.get("access-control-allow-methods", "")
    assert "content-type" in response.headers.get("access-control-allow-headers", "").lower()


def test_cors_preflight_with_authorization_header():
    """Verify that preflight OPTIONS request with Authorization header is accepted with 200 OK."""
    client = TestClient(app)
    response = client.options(
        "/api/hosts",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    allow_hdrs = response.headers.get("access-control-allow-headers", "").lower()
    assert "authorization" in allow_hdrs or allow_hdrs == "*"


def test_cors_actual_request_allowed_origin():
    """Verify that a GET request from trusted origin has allow-origin and expose-headers."""
    client = TestClient(app)
    response = client.get(
        "/api/hosts",
        headers={
            "Origin": "http://localhost:5173",
        },
    )
    assert response.status_code == 401
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"
    assert "content-disposition" in response.headers.get("access-control-expose-headers", "").lower()


def test_cors_untrusted_origin_rejected():
    """Verify that an untrusted origin does NOT receive access-control-allow-origin."""
    client = TestClient(app)
    response = client.options(
        "/api/hosts",
        headers={
            "Origin": "https://malicious-attacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Untrusted origin will not have access-control-allow-origin header
    assert response.headers.get("access-control-allow-origin") is None


def test_default_cors_origins_contain_local_dev_ports(monkeypatch):
    """Verify default CORS list contains standard Vite and API ports."""
    monkeypatch.delenv("SECURE_SMTP_CORS_ORIGINS", raising=False)
    defaults = Settings(_env_file=None).cors_origins
    assert "http://localhost:5173" in defaults
    assert "http://127.0.0.1:5173" in defaults
    assert "http://localhost:8000" in defaults
