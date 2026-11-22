"""
Unit tests for MongoDB authentication, URI builder, password masking,
and health status reporting.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from secure_smtp.api.main import app
from secure_smtp.db.mongodb import (
    build_mongo_uri,
    get_masked_mongo_uri,
    get_mongo_auth_status,
)


def test_build_mongo_uri_unauthenticated():
    """Verify clean URI construction when no credentials are provided."""
    uri = build_mongo_uri(
        user="",
        password="",
        host="localhost",
        port=27017,
        db_name="secure_smtp",
    )
    assert uri == "mongodb://localhost:27017/secure_smtp"


def test_build_mongo_uri_with_credentials():
    """Verify authenticated URI with authSource and authMechanism."""
    uri = build_mongo_uri(
        user="my_user",
        password="my_password",
        host="127.0.0.1",
        port=27017,
        db_name="secure_smtp",
        auth_db="admin",
        auth_mechanism="SCRAM-SHA-256",
    )
    assert (
        uri
        == "mongodb://my_user:my_password@127.0.0.1:27017/secure_smtp?authSource=admin&authMechanism=SCRAM-SHA-256"
    )


def test_build_mongo_uri_percent_encoding():
    """Verify special characters in passwords and usernames are safely percent-encoded."""
    uri = build_mongo_uri(
        user="user@domain.com",
        password="p@ss:w/ord?!#",
        host="mongo.internal",
        port=27018,
        db_name="secure_smtp",
        auth_db="admin",
        auth_mechanism="SCRAM-SHA-256",
    )
    # user@domain.com -> user%40domain.com
    assert "user%40domain.com" in uri
    # p@ss:w/ord?!# -> p%40ss%3Aw%2Ford%3F%21%23
    assert "p%40ss%3Aw%2Ford%3F%21%23" in uri


def test_get_masked_mongo_uri_redaction():
    """Verify passwords are masked with '******'."""
    raw_uri = "mongodb://secure_admin:SuperSecret123!@localhost:27017/secure_smtp?authSource=admin"
    masked = get_masked_mongo_uri(raw_uri)
    assert "SuperSecret123!" not in masked
    assert masked == "mongodb://secure_admin:******@localhost:27017/secure_smtp?authSource=admin"


def test_get_masked_mongo_uri_unauthenticated():
    """Verify unauthenticated URI remains unchanged when no password exists."""
    raw_uri = "mongodb://localhost:27017/secure_smtp"
    masked = get_masked_mongo_uri(raw_uri)
    assert masked == "mongodb://localhost:27017/secure_smtp"


def test_get_mongo_auth_status_structure(monkeypatch):
    """Verify get_mongo_auth_status returns expected keys and types."""
    from secure_smtp.db import mongodb

    fake_client = MagicMock()
    fake_client.admin.command.return_value = {"ok": 1.0}
    monkeypatch.setattr(mongodb, "get_mongo_client", lambda: fake_client)
    status = get_mongo_auth_status()
    assert "status" in status
    assert "database" in status
    assert "auth_enabled" in status
    assert "uri_masked" in status
    # When password is present in masked URI, ensure actual secret is not leaked
    if "@" in status["uri_masked"]:
        assert ":******@" in status["uri_masked"]


def test_health_endpoint_does_not_expose_database_or_identity_details(monkeypatch):
    from secure_smtp.api.routers import system

    monkeypatch.setattr(
        system,
        "get_mongo_auth_status",
        lambda: {
            "status": "connected",
            "uri_masked": "mongodb://internal",
            "authenticated_user": "secret-user",
        },
    )
    monkeypatch.setattr(
        system,
        "get_settings",
        lambda: SimpleNamespace(
            clerk_issuer="https://identity.example.test",
            pilot_org_id="org_pilot",
            clerk_authorized_parties=["https://pilot.example.test"],
        ),
    )
    response = TestClient(app).get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "secure-smtp"}


def test_health_endpoint_signals_database_failure(monkeypatch):
    from secure_smtp.api.routers import system

    monkeypatch.setattr(system, "get_mongo_auth_status", lambda: {"status": "disconnected"})
    response = TestClient(app).get("/api/health")
    assert response.status_code == 503
    assert response.json() == {"detail": "Service not ready"}


def test_health_endpoint_signals_unconfigured_identity(monkeypatch):
    from secure_smtp.api.routers import system

    monkeypatch.setattr(system, "get_mongo_auth_status", lambda: {"status": "connected"})
    monkeypatch.setattr(
        system,
        "get_settings",
        lambda: SimpleNamespace(
            clerk_issuer="",
            pilot_org_id="",
            clerk_authorized_parties=[],
        ),
    )
    assert TestClient(app).get("/api/health").status_code == 503
