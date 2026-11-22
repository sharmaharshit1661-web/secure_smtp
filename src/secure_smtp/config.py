"""
Centralized Configuration & Settings Module — Secure SMTP.

Replaces scattered os.environ.get() calls with a validated, strongly-typed
Pydantic Settings configuration supporting environment variables, .env files,
validation, and sensible security defaults.
"""

from __future__ import annotations

import re
import urllib.parse
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central application settings for Secure SMTP.
    Supports environment variables with prefix SECURE_SMTP_ and backward-compatible aliases.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.clerk-local"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Application Metadata ──
    app_name: str = Field(default="Secure SMTP", description="Application display name")
    app_version: str = Field(default="0.1.0", description="Application semantic version")
    debug: bool = Field(default=False, description="Debug mode")
    enable_live_lab: bool = Field(
        default=False,
        validation_alias=AliasChoices("SECURE_SMTP_ENABLE_LIVE_LAB", "ENABLE_LIVE_LAB"),
        description="Whether to auto-start in-process live mail simulation lab on ports 2525-2528",
    )

    # ── API Authentication ──
    api_key: str = Field(
        default="",
        validation_alias=AliasChoices("SECURE_SMTP_API_KEY", "API_KEY"),
        description="Master API authentication key",
    )
    auth_required: bool = Field(
        default=True,
        validation_alias=AliasChoices("SECURE_SMTP_AUTH_REQUIRED", "AUTH_REQUIRED"),
        description="Whether API authentication is enforced on sensitive endpoints",
    )

    auth_provider: Literal["clerk", "keycloak", "mongodb", "native"] = Field(
        default="clerk", validation_alias="SECURE_SMTP_AUTH_PROVIDER"
    )
    offline_issuer: str = Field(default="", validation_alias="SECURE_SMTP_OFFLINE_ISSUER")
    offline_jwks_url: str = Field(default="", validation_alias="SECURE_SMTP_OFFLINE_JWKS_URL")

    clerk_issuer: str = Field(default="", validation_alias="SECURE_SMTP_CLERK_ISSUER")
    clerk_audience: str = Field(default="", validation_alias="SECURE_SMTP_CLERK_AUDIENCE")
    clerk_authorized_parties: list[str] | str = Field(
        default_factory=list, validation_alias="SECURE_SMTP_CLERK_AUTHORIZED_PARTIES"
    )
    public_registration: bool = Field(
        default=True, validation_alias="SECURE_SMTP_PUBLIC_REGISTRATION"
    )
    pilot_org_id: str = Field(default="", validation_alias="SECURE_SMTP_PILOT_ORG_ID")
    max_upload_bytes: int = Field(
        default=25 * 1024 * 1024,
        ge=1,
        le=100 * 1024 * 1024,
        validation_alias="SECURE_SMTP_MAX_UPLOAD_BYTES",
    )
    max_capture_packets: int = Field(
        default=100000, ge=1, validation_alias="SECURE_SMTP_MAX_CAPTURE_PACKETS"
    )
    max_capture_streams: int = Field(
        default=2000, ge=1, validation_alias="SECURE_SMTP_MAX_CAPTURE_STREAMS"
    )
    analysis_timeout_seconds: int = Field(
        default=120, ge=1, validation_alias="SECURE_SMTP_ANALYSIS_TIMEOUT_SECONDS"
    )

    agent_allow_insecure_local: bool = Field(
        default=False, validation_alias="SECURE_SMTP_AGENT_ALLOW_INSECURE_LOCAL"
    )
    retention_days: int = Field(
        default=30, ge=1, le=3650, validation_alias="SECURE_SMTP_RETENTION_DAYS"
    )
    agent_offline_seconds: int = Field(
        default=90, ge=30, validation_alias="SECURE_SMTP_AGENT_OFFLINE_SECONDS"
    )
    neo4j_uri: str = Field(default="", validation_alias="SECURE_SMTP_NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", validation_alias="SECURE_SMTP_NEO4J_USER")
    neo4j_password: str = Field(default="", validation_alias="SECURE_SMTP_NEO4J_PASSWORD")

    # ── Alerting & Webhooks ──
    alerts_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("SECURE_SMTP_ALERTS_ENABLED", "ALERTS_ENABLED"),
        description="Whether real-time security alerts/webhooks are enabled",
    )
    alert_webhook_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_WEBHOOK_URL", "ALERT_WEBHOOK_URL"),
        description="Incoming webhook URL for alerts (Slack, Teams, Discord, or generic)",
    )
    alert_webhook_secret: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_WEBHOOK_SECRET", "ALERT_WEBHOOK_SECRET"),
        description="Optional shared secret for HMAC-SHA256 signature on webhook payloads",
    )
    alert_min_severity: str = Field(
        default="HIGH",
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_MIN_SEVERITY", "ALERT_MIN_SEVERITY"),
        description="Minimum finding severity to trigger alert (LOW, MEDIUM, HIGH, CRITICAL)",
    )
    alert_risk_threshold: float = Field(
        default=75.0,
        validation_alias=AliasChoices("SECURE_SMTP_ALERT_RISK_THRESHOLD", "ALERT_RISK_THRESHOLD"),
        description="Minimum session risk score to trigger alert (0-100)",
    )

    # ── CORS Settings ──
    cors_origins: list[str] | str = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        validation_alias=AliasChoices("SECURE_SMTP_CORS_ORIGINS", "CORS_ORIGINS"),
        description="Allowed CORS origin URLs",
    )
    cors_headers: list[str] | str = Field(
        default_factory=lambda: ["*"],
        validation_alias=AliasChoices("SECURE_SMTP_CORS_HEADERS", "CORS_HEADERS"),
        description="Allowed CORS request headers",
    )

    @field_validator("cors_origins", "cors_headers", "clerk_authorized_parties", mode="before")
    @classmethod
    def parse_comma_separated_list(cls, v):
        import json

        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    inner = v[1:-1].strip()
                    return [
                        item.strip().strip("\"'")
                        for item in inner.split(",")
                        if item.strip().strip("\"'")
                    ]
            return [item.strip() for item in v.split(",") if item.strip()]
        if isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return v

    # ── Storage & Directories ──
    upload_dir: Path = Field(
        default=Path("/tmp/secure_smtp_uploads"),
        validation_alias=AliasChoices(
            "SECURE_SMTP_UPLOAD_DIR", "SECUREMAILSCOPE_UPLOAD_DIR", "UPLOAD_DIR"
        ),
        description="Directory for temporary uploaded PCAP files",
    )
    reports_dir: Path = Field(
        default=Path("/tmp/secure_smtp_reports"),
        validation_alias=AliasChoices(
            "SECURE_SMTP_REPORTS_DIR", "SECUREMAILSCOPE_REPORTS_DIR", "REPORTS_DIR"
        ),
        description="Directory for generated PDF/HTML/JSON analysis reports",
    )

    # ── MongoDB Settings ──
    mongo_host: str = Field(
        default="localhost",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_HOST", "MONGO_HOST"),
        description="MongoDB server hostname or IP",
    )
    mongo_port: int = Field(
        default=27017,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_PORT", "MONGO_PORT"),
        description="MongoDB server port",
    )
    mongo_db: str = Field(
        default="secure_smtp",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_DB", "MONGO_DB"),
        description="Application database name",
    )
    mongo_user: str = Field(
        default="",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_USER", "MONGO_USER"),
        description="MongoDB authentication username",
    )
    mongo_password: str = Field(
        default="",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_PASSWORD", "MONGO_PASSWORD"),
        description="MongoDB authentication password",
    )
    mongo_auth_db: str = Field(
        default="admin",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_DB", "MONGO_AUTH_DB"),
        description="Database to authenticate against (authSource)",
    )
    mongo_auth_mechanism: str = Field(
        default="SCRAM-SHA-256",
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_MECHANISM", "MONGO_AUTH_MECHANISM"),
        description="MongoDB authentication mechanism",
    )
    mongo_auth_required: bool = Field(
        default=False,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_AUTH_REQUIRED", "MONGO_AUTH_REQUIRED"),
        description="Whether MongoDB authentication is strictly required",
    )
    mongo_uri: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SECURE_SMTP_MONGO_URI", "MONGO_URI"),
        description="Explicit MongoDB connection URI (overrides individual host/user settings)",
    )

    # ── Derived Connection Helpers ──

    def get_mongo_connection_uri(self) -> str:
        """
        Build a well-formed MongoDB connection URI, safely percent-encoding
        special characters in usernames and passwords.
        """
        if self.mongo_uri and self.mongo_uri.strip():
            return self.mongo_uri.strip()

        if self.mongo_user and self.mongo_password:
            user_enc = urllib.parse.quote_plus(self.mongo_user)
            pwd_enc = urllib.parse.quote_plus(self.mongo_password)
            query_params = []
            if self.mongo_auth_db:
                query_params.append(f"authSource={urllib.parse.quote_plus(self.mongo_auth_db)}")
            if self.mongo_auth_mechanism:
                query_params.append(
                    f"authMechanism={urllib.parse.quote_plus(self.mongo_auth_mechanism)}"
                )
            query_str = f"?{'&'.join(query_params)}" if query_params else ""
            return f"mongodb://{user_enc}:{pwd_enc}@{self.mongo_host}:{self.mongo_port}/{self.mongo_db}{query_str}"
        elif self.mongo_user:
            user_enc = urllib.parse.quote_plus(self.mongo_user)
            query_params = []
            if self.mongo_auth_db:
                query_params.append(f"authSource={urllib.parse.quote_plus(self.mongo_auth_db)}")
            query_str = f"?{'&'.join(query_params)}" if query_params else ""
            return f"mongodb://{user_enc}@{self.mongo_host}:{self.mongo_port}/{self.mongo_db}{query_str}"
        else:
            return f"mongodb://{self.mongo_host}:{self.mongo_port}/{self.mongo_db}"

    def get_masked_mongo_uri(self) -> str:
        """Return the connection URI with the password component safely redacted."""
        uri = self.get_mongo_connection_uri()
        return re.sub(r":([^/@]+)@", r":******@", uri)


@lru_cache
def get_settings() -> Settings:
    """Cached singleton getter for application settings."""
    return Settings()
