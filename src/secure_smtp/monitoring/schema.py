"""Closed telemetry schema: no arbitrary payloads, mail bodies, headers or credentials."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator

Short = Annotated[str, Field(max_length=160)]


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CertificateMetadata(ClosedModel):
    chain_position: int = Field(ge=0, le=10)
    not_before: AwareDatetime | None = None
    not_after: AwareDatetime | None = None
    public_key_algorithm: Literal["RSA", "EC", "ECDSA", "DSA", "Ed25519", "Ed448", "unknown"] = (
        "unknown"
    )
    key_length_bits: int = Field(default=0, ge=0, le=16384)
    signature_algorithm: Short = ""
    self_signed: bool | None = None
    # Never accept a collector's unsupported assertion of trust validation.
    chain_valid: None = None


class HandshakeMetadata(ClosedModel):
    tls_version_negotiated: Literal["", "SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"] = ""
    cipher_suite_negotiated: Short = ""
    key_exchange_type: Literal["unknown", "rsa", "dhe", "ecdhe"] = "unknown"
    forward_secrecy: bool | None = None
    visibility_limited: bool = False
    ja3: Annotated[str, Field(pattern=r"^([a-f0-9]{32})?$")] = ""
    ja3s: Annotated[str, Field(pattern=r"^([a-f0-9]{32})?$")] = ""


class Observation(ClosedModel):
    event_id: UUID
    observed_at: AwareDatetime
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=1, le=65535)
    dst_port: int = Field(ge=1, le=65535)
    protocol: Literal["smtp", "imap", "pop3"]
    tls_mode: Literal["none", "implicit", "starttls", "unknown"]
    starttls_advertised: bool = False
    starttls_completed: bool = False
    capture_complete: bool = False
    handshake: HandshakeMetadata | None = None
    certificates: list[CertificateMetadata] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def consistency(self):
        if self.observed_at > datetime.now(UTC) + timedelta(minutes=5):
            raise ValueError("Observation timestamp is in the future")
        if self.tls_mode in ("none", "unknown") and (
            self.handshake or self.certificates or self.starttls_completed
        ):
            raise ValueError("TLS metadata contradicts transport state")
        if self.starttls_completed and self.tls_mode != "starttls":
            raise ValueError("STARTTLS completion requires STARTTLS mode")
        return self


class ObservationBatch(ClosedModel):
    batch_id: UUID
    observations: list[Observation] = Field(min_length=1, max_length=25)

    @model_validator(mode="after")
    def unique_events(self):
        if len({o.event_id for o in self.observations}) != len(self.observations):
            raise ValueError("Duplicate event IDs in batch")
        return self


class Heartbeat(ClosedModel):
    version: Literal["1"] = "1"
    queued_events: int = Field(default=0, ge=0, le=100000)
    dropped_events: int = Field(default=0, ge=0)
    capture_errors: int = Field(default=0, ge=0)
    capture_active: bool = False
