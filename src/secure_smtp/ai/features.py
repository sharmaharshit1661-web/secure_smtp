"""
Feature vector builder — Stage 5.

Constructs the per-session feature vector from Phase 1+2 output
for input to both the risk scoring and anomaly detection models.
Feature vector per TAD §6.1.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC

import numpy as np

from secure_smtp.db.models import (
    Certificate,
    Finding,
    Session,
    Severity,
    TLSHandshake,
    TLSMode,
)

logger = logging.getLogger(__name__)

# ── Feature definitions ──

FEATURE_NAMES = [
    "tls_version_ordinal",
    "cipher_strength_score",
    "forward_secrecy",
    "cert_key_length",
    "cert_sig_algo_weak",
    "days_to_cert_expiry",
    "cert_chain_length",
    "cert_self_signed",
    "extension_count",
    "starttls_expected_but_absent",
    "rule_finding_count",
    "rule_finding_max_severity_ordinal",
    "has_tls",
]

# TLS version ordinal mapping (higher = more modern = more secure)
TLS_VERSION_ORDINAL = {
    "": 0,
    "SSLv3": 1,
    "TLS1.0": 2,
    "TLS1.1": 3,
    "TLS1.2": 4,
    "TLS1.3": 5,
}

# Severity ordinal for feature encoding
SEVERITY_ORDINAL = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Weak signature algorithms
WEAK_SIG_ALGOS = {"md5", "sha1"}

# Cipher strength heuristic scores (0-10)
CIPHER_STRENGTH = {
    "NULL": 0,
    "EXPORT": 1,
    "DES": 2,
    "RC4": 3,
    "3DES": 4,
    "AES_128_CBC": 6,
    "AES_256_CBC": 7,
    "AES_128_GCM": 9,
    "AES_256_GCM": 10,
    "CHACHA20": 10,
}


@dataclass
class FeatureVector:
    """Per-session feature vector for ML models."""

    session_id: int = 0
    values: np.ndarray = field(default_factory=lambda: np.zeros(len(FEATURE_NAMES)))
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))

    def to_dict(self) -> dict[str, float]:
        """Convert to a name→value dictionary."""
        return dict(zip(self.feature_names, self.values.tolist()))


def _score_cipher_strength(cipher_name: str) -> float:
    """Score a cipher suite's strength on a 0-10 scale."""
    upper = cipher_name.upper()

    # Check from strongest to weakest
    for pattern, score in sorted(CIPHER_STRENGTH.items(), key=lambda x: -x[1]):
        if pattern in upper:
            return score

    # Default: moderate strength for unknown ciphers
    return 5.0


def build_feature_vector(
    session: Session,
    handshake: TLSHandshake | None,
    certificates: list[Certificate],
    findings: list[Finding],
) -> FeatureVector:
    """
    Build the feature vector for a single session.

    Features per TAD §6.1:
    - tls_version_ordinal
    - cipher_strength_score
    - forward_secrecy (0/1)
    - cert_key_length
    - cert_sig_algo_weak (0/1)
    - days_to_cert_expiry
    - cert_chain_length
    - cert_self_signed (0/1)
    - extension_count
    - starttls_expected_but_absent (0/1)
    - rule_finding_count
    - rule_finding_max_severity_ordinal
    - has_tls (0/1)
    """
    features = np.zeros(len(FEATURE_NAMES))
    fv = FeatureVector(session_id=session.id or 0, values=features)

    # ── TLS-dependent features ──

    if handshake is not None and session.tls_mode != TLSMode.NONE:
        # TLS version ordinal
        features[0] = TLS_VERSION_ORDINAL.get(handshake.tls_version_negotiated, 0)

        # Cipher strength score
        features[1] = _score_cipher_strength(handshake.cipher_suite_negotiated)

        # Forward secrecy
        features[2] = 1.0 if handshake.forward_secrecy else 0.0

        # Extension count
        features[8] = len(handshake.extensions_dict) if handshake.extensions else 0

        # Has TLS
        features[12] = 1.0

    # ── Certificate features ──

    if certificates:
        leaf_cert = certificates[0]  # First cert is the leaf

        # Key length
        features[3] = float(leaf_cert.key_length_bits)

        # Weak signature algorithm
        features[4] = 1.0 if leaf_cert.signature_algorithm in WEAK_SIG_ALGOS else 0.0

        # Days to expiry
        if leaf_cert.not_after:
            from datetime import datetime

            now = datetime.now(UTC)
            not_after = leaf_cert.not_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            delta = (not_after - now).days
            features[5] = float(delta)

        # Chain length
        features[6] = float(len(certificates))

        # Self-signed
        features[7] = 1.0 if leaf_cert.self_signed else 0.0

    # ── STARTTLS features ──

    features[9] = 1.0 if (session.starttls_advertised and not session.starttls_completed) else 0.0

    # ── Finding features ──

    features[10] = float(len(findings))

    if findings:
        max_severity = max(SEVERITY_ORDINAL.get(f.severity, 0) for f in findings)
        features[11] = float(max_severity)

    return fv


def build_feature_matrix(
    sessions_data: list[tuple[Session, TLSHandshake | None, list[Certificate], list[Finding]]],
) -> tuple[np.ndarray, list[int]]:
    """
    Build a feature matrix from multiple sessions.

    Args:
        sessions_data: List of (session, handshake, certificates, findings) tuples.

    Returns:
        Tuple of (feature_matrix, session_ids).
    """
    vectors = []
    session_ids = []

    for session, handshake, certificates, findings in sessions_data:
        fv = build_feature_vector(session, handshake, certificates, findings)
        vectors.append(fv.values)
        session_ids.append(fv.session_id)

    if vectors:
        return np.array(vectors), session_ids
    return np.empty((0, len(FEATURE_NAMES))), []
