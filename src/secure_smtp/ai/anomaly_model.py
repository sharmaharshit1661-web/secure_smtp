"""
Anomaly detection model — Stage 5.

Uses Isolation Forest for unsupervised anomaly detection on the
per-session feature vector. Supports per-host baselining where
enough sessions exist (≥20), with global baseline fallback.
Per TAD §6.3.
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from secure_smtp.ai.features import FeatureVector
from secure_smtp.db.models import AnomalyScore

logger = logging.getLogger(__name__)

# Minimum sessions per host to enable per-host baselining
MIN_HOST_SESSIONS = 20

# Anomaly threshold (IsolationForest scores < this are anomalous)
ANOMALY_THRESHOLD = -0.1


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector with per-host baselining.

    Per TAD §6.3: uses per-host baselines where ≥20 prior sessions exist
    for that host, falls back to global baseline otherwise.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.global_model: IsolationForest | None = None
        self.host_models: dict[str, IsolationForest] = {}
        self._is_fitted = False

    def fit_global(self, feature_matrix: np.ndarray) -> None:
        """
        Fit the global baseline anomaly model.

        Args:
            feature_matrix: (N, num_features) feature matrix from all sessions.
        """
        if len(feature_matrix) < 5:
            logger.warning(
                "Insufficient data for global anomaly model (%d samples)", len(feature_matrix)
            )
            return

        self.global_model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        self.global_model.fit(feature_matrix)
        self._is_fitted = True
        logger.info("Fitted global anomaly model on %d sessions", len(feature_matrix))

    def fit_host(self, host_ip: str, feature_matrix: np.ndarray) -> None:
        """
        Fit a per-host anomaly model if enough sessions exist.

        Args:
            host_ip: The host's IP address or hostname.
            feature_matrix: Feature matrix for this host's sessions.
        """
        if len(feature_matrix) < MIN_HOST_SESSIONS:
            logger.debug(
                "Skipping per-host model for %s (%d < %d sessions)",
                host_ip,
                len(feature_matrix),
                MIN_HOST_SESSIONS,
            )
            return

        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        model.fit(feature_matrix)
        self.host_models[host_ip] = model
        logger.info(
            "Fitted per-host anomaly model for %s on %d sessions", host_ip, len(feature_matrix)
        )

    def score_session(
        self,
        feature_vector: FeatureVector,
        host_ip: str = "",
    ) -> AnomalyScore:
        """
        Compute anomaly score for a single session.

        Uses per-host model if available, otherwise global model.
        If no model is fitted, returns a default non-anomalous score.

        Args:
            feature_vector: The session's feature vector.
            host_ip: The host IP for per-host baselining.

        Returns:
            AnomalyScore with score and anomaly flag.
        """
        features = feature_vector.values.reshape(1, -1)
        baseline = "global"

        # Try per-host model first
        model = self.host_models.get(host_ip)
        if model is not None:
            baseline = f"host:{host_ip}"
        elif self.global_model is not None:
            model = self.global_model
        else:
            # No model fitted — return default
            return AnomalyScore(
                session_id=feature_vector.session_id,
                anomaly_score=0.0,
                is_anomalous=False,
                baseline_reference="none (no model fitted)",
            )

        try:
            # IsolationForest.decision_function returns negative values for anomalies
            score = float(model.decision_function(features)[0])
            is_anomalous = score < ANOMALY_THRESHOLD

            return AnomalyScore(
                session_id=feature_vector.session_id,
                anomaly_score=round(score, 4),
                is_anomalous=is_anomalous,
                baseline_reference=baseline,
            )

        except Exception as e:
            logger.warning(
                "Anomaly scoring failed for session %d: %s", feature_vector.session_id, e
            )
            return AnomalyScore(
                session_id=feature_vector.session_id,
                anomaly_score=0.0,
                is_anomalous=False,
                baseline_reference=f"error: {e!s}",
            )

    def score_batch(
        self,
        feature_vectors: list[FeatureVector],
        host_ips: list[str],
    ) -> list[AnomalyScore]:
        """Score multiple sessions at once."""
        return [self.score_session(fv, host_ip) for fv, host_ip in zip(feature_vectors, host_ips)]

    def save(self, path: str | Path) -> None:
        """Save the anomaly detector state."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "global_model": self.global_model,
            "host_models": self.host_models,
            "contamination": self.contamination,
        }
        with open(path, "wb") as f:
            pickle.dump(state, f)
        logger.info("Saved anomaly detector to %s", path)

    def load(self, path: str | Path) -> None:
        """Load a saved anomaly detector state."""
        path = Path(path)
        if not path.exists():
            logger.warning("Anomaly detector file not found: %s", path)
            return
        try:
            with open(path, "rb") as f:
                state = pickle.load(f)
            self.global_model = state.get("global_model")
            self.host_models = state.get("host_models", {})
            self.contamination = state.get("contamination", 0.1)
            self._is_fitted = self.global_model is not None
            logger.info("Loaded anomaly detector from %s", path)
        except Exception as e:
            logger.error("Failed to load anomaly detector: %s", e)
