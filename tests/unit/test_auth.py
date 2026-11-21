"""
Unit tests for API authentication and authorization.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from secure_smtp.api.auth import DEFAULT_DEV_API_KEY
from secure_smtp.api.main import app

client = TestClient(app)


def test_health_endpoint_public_unauthenticated():
    """Health check endpoint should be accessible without any API key."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "secure-smtp"


def test_protected_endpoint_missing_auth_returns_401():
    """Accessing protected endpoints without auth returns 401 Unauthorized."""
    response = client.get("/api/hosts")
    assert response.status_code == 401
    assert "Missing API authentication" in response.json()["detail"]


def test_protected_endpoint_with_valid_api_key_header():
    """Valid X-API-Key header grants access."""
    response = client.get(
        "/api/hosts",
        headers={"X-API-Key": DEFAULT_DEV_API_KEY},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_protected_endpoint_with_valid_bearer_token():
    """Valid Authorization: Bearer <key> grants access."""
    response = client.get(
        "/api/hosts",
        headers={"Authorization": f"Bearer {DEFAULT_DEV_API_KEY}"},
    )
    assert response.status_code == 200


def test_query_string_key_is_rejected():
    """Secrets in URLs must not authenticate a browser."""
    response = client.get(f"/api/hosts?api_key={DEFAULT_DEV_API_KEY}")
    assert response.status_code == 401


def test_protected_endpoint_with_invalid_api_key_returns_403():
    """Invalid API key returns 403 Forbidden."""
    response = client.get(
        "/api/hosts",
        headers={"X-API-Key": "invalid_wrong_key_123"},
    )
    assert response.status_code == 403
    assert "Invalid API key" in response.json()["detail"]


def test_analyze_endpoint_requires_auth():
    """POST /api/analyze requires authentication."""
    response = client.post("/api/analyze")
    assert response.status_code == 401
