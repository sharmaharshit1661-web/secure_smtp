"""
Unit tests for the centralized Pydantic Settings configuration module.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from secure_smtp.config import Settings, get_settings


def test_default_settings():
    """Verify default settings initialization."""
    settings = Settings()
    assert settings.app_name == "Secure SMTP"
    assert settings.app_version == "0.1.0"
    assert settings.api_key == "securesmtp_live_secret_key"
    assert settings.auth_required is True
    assert settings.mongo_host == "localhost"
    assert settings.mongo_port == 27017
    assert settings.mongo_db == "secure_smtp"
    assert settings.mongo_auth_db == "admin"
    assert settings.mongo_auth_mechanism == "SCRAM-SHA-256"
    assert isinstance(settings.upload_dir, Path)
    assert isinstance(settings.reports_dir, Path)


def test_cors_origins_comma_separated_parsing():
    """Verify comma-separated string is parsed into a list."""
    settings = Settings(cors_origins="https://app.securesmtp.io, https://console.securesmtp.io")
    assert settings.cors_origins == [
        "https://app.securesmtp.io",
        "https://console.securesmtp.io",
    ]


def test_cors_headers_comma_separated_parsing():
    """Verify comma-separated headers are parsed into a list."""
    settings = Settings(cors_headers="X-API-Key, Authorization, Content-Type")
    assert settings.cors_headers == ["X-API-Key", "Authorization", "Content-Type"]


def test_mongo_uri_assembly_unauthenticated():
    """Verify connection URI without authentication."""
    settings = Settings(
        _env_file=None,
        mongo_uri=None,
        mongo_user="",
        mongo_password="",
        mongo_host="10.0.0.5",
        mongo_port=27018,
        mongo_db="audit_logs",
    )
    assert settings.get_mongo_connection_uri() == "mongodb://10.0.0.5:27018/audit_logs"


def test_mongo_uri_assembly_authenticated():
    """Verify connection URI with credentials and special characters."""
    settings = Settings(
        _env_file=None,
        mongo_uri=None,
        mongo_user="app_user",
        mongo_password="p@ss:w/ord?!",
        mongo_host="db.internal",
        mongo_port=27017,
        mongo_db="secure_smtp",
        mongo_auth_db="admin",
        mongo_auth_mechanism="SCRAM-SHA-256",
    )
    uri = settings.get_mongo_connection_uri()
    assert "mongodb://app_user:p%40ss%3Aw%2Ford%3F%21@db.internal:27017/secure_smtp" in uri
    assert "authSource=admin" in uri
    assert "authMechanism=SCRAM-SHA-256" in uri

    masked = settings.get_masked_mongo_uri()
    assert "p@ss:w/ord?!" not in masked
    assert "p%40ss%3Aw%2Ford%3F%21" not in masked
    assert "mongodb://app_user:******@db.internal:27017/secure_smtp" in masked


def test_mongo_uri_auto_normalization_with_special_characters():
    """Verify raw URI with unescaped special characters (#, @, spaces) is properly normalized."""
    raw_atlas_uri = "mongodb+srv://testUser:spec!al#pwd@123 @cluster0.example.mongodb.net/"
    settings = Settings(_env_file=None, mongo_uri=raw_atlas_uri)
    normalized = settings.get_mongo_connection_uri()
    assert "spec%21al%23pwd%40123" in normalized
    assert "cluster0.example.mongodb.net" in normalized
    assert " " not in normalized


def test_explicit_mongo_uri_override():
    """Verify explicit mongo_uri takes precedence over components."""
    settings = Settings(
        mongo_uri="mongodb+srv://cluster0.example.net/production?retryWrites=true"
    )
    assert (
        settings.get_mongo_connection_uri()
        == "mongodb+srv://cluster0.example.net/production?retryWrites=true"
    )


def test_legacy_securemailscope_config_bridge():
    """Verify backward-compatible import from securemailscope.config."""
    from securemailscope.config import Settings as LegacySettings
    from securemailscope.config import get_settings as legacy_get_settings

    assert LegacySettings is Settings
    s = legacy_get_settings()
    assert isinstance(s, Settings)
    assert s.app_name == "Secure SMTP"
