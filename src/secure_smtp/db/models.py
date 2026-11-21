"""
Database models for Secure SMTP.

Pydantic v2 document models for MongoDB storage: Host, Session, TLSHandshake, Certificate,
Finding, RiskScore, AnomalyScore, AnalysisJob.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

# ── Enums ──────────────────────────────────────────────────────────────────


class ProtocolType(str, Enum):
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    UNKNOWN = "unknown"


class TLSMode(str, Enum):
    IMPLICIT = "implicit"
    STARTTLS = "starttls"
    NONE = "none"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class KeyExchangeType(str, Enum):
    ECDHE = "ecdhe"
    DHE = "dhe"
    RSA = "rsa"
    UNKNOWN = "unknown"


# ── Severity Weights (TAD §6.2) ───────────────────────────────────────────

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 10,
}


# ── Models ─────────────────────────────────────────────────────────────────


class Host(BaseModel):
    """Rollup entity for per-host aggregate scoring."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: int | None = None
    ip_or_hostname: str
    session_count: int = 0
    aggregate_risk_score: float = 0.0


class TLSHandshake(BaseModel):
    """TLS handshake details for a session."""

    id: int | None = None
    session_id: int | None = None

    tls_version_offered: str = "[]"  # JSON list of versions from ClientHello
    tls_version_negotiated: str = ""
    cipher_suite_negotiated: str = ""
    key_exchange_type: KeyExchangeType = KeyExchangeType.UNKNOWN
    forward_secrecy: bool = False

    ja3: str = ""
    ja3s: str = ""
    ja4: str = ""
    ja4s: str = ""

    extensions: str = "{}"  # JSON string
    visibility_limited: bool = False

    @property
    def tls_versions_offered_list(self) -> list[str]:
        """Parse the JSON-encoded list of offered TLS versions."""
        try:
            return json.loads(self.tls_version_offered)
        except (json.JSONDecodeError, TypeError):
            return []

    @tls_versions_offered_list.setter
    def tls_versions_offered_list(self, versions: list[str]) -> None:
        self.tls_version_offered = json.dumps(versions)

    @property
    def extensions_dict(self) -> dict:
        """Parse the JSON-encoded extensions."""
        try:
            return json.loads(self.extensions)
        except (json.JSONDecodeError, TypeError):
            return {}


class Certificate(BaseModel):
    """X.509 certificate from the TLS handshake."""

    id: int | None = None
    handshake_id: int | None = None
    chain_position: int = 0

    subject: str = ""
    issuer: str = ""
    san: str = "[]"  # JSON list of Subject Alternative Names
    not_before: datetime | None = None
    not_after: datetime | None = None
    public_key_algorithm: str = ""
    key_length_bits: int = 0
    signature_algorithm: str = ""
    self_signed: bool = False
    chain_valid: bool = True

    @property
    def san_list(self) -> list[str]:
        """Parse the JSON-encoded SAN list."""
        try:
            return json.loads(self.san)
        except (json.JSONDecodeError, TypeError):
            return []


class Finding(BaseModel):
    """A rule-engine finding for a session."""

    id: int | None = None
    session_id: int | None = None
    rule_id: str = ""
    severity: Severity = Severity.INFO
    evidence: str = "{}"  # JSON string
    recommendation_text: str = ""
    message: str = ""

    @property
    def recommendation(self) -> str:
        return self.recommendation_text


class RiskScore(BaseModel):
    """AI-assisted risk score for a session."""

    id: int | None = None
    session_id: int | None = None
    score_0_100: float = 0.0
    tier: RiskTier = RiskTier.LOW
    feature_attribution: str = "{}"  # JSON SHAP values

    @property
    def score(self) -> float:
        return self.score_0_100

    @property
    def feature_attribution_dict(self) -> dict:
        try:
            return json.loads(self.feature_attribution)
        except (json.JSONDecodeError, TypeError):
            return {}


class AnomalyScore(BaseModel):
    """Isolation Forest anomaly score for a session."""

    id: int | None = None
    session_id: int | None = None
    anomaly_score: float = 0.0
    is_anomalous: bool = False
    baseline_reference: str = "global"

    @property
    def score(self) -> float:
        return self.anomaly_score


class Session(BaseModel):
    """A single email protocol session extracted from the PCAP."""

    id: int | None = None
    job_id: str = ""
    pcap_source: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0

    protocol: ProtocolType = ProtocolType.UNKNOWN
    tls_mode: TLSMode = TLSMode.NONE
    starttls_advertised: bool = False
    starttls_completed: bool = False

    host_id: int | None = None

    # Embedded Documents for MongoDB
    handshake: Optional[TLSHandshake] = None
    certificates: list[Certificate] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    anomaly_score: Optional[AnomalyScore] = None


class AnalysisJob(BaseModel):
    """Tracks the status of a PCAP analysis job."""

    id: int | None = None
    job_id: str
    pcap_filename: str = ""
    status: str = "queued"  # queued | running | done | failed
    error_message: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
