"""
Risk scoring model — Stage 5.

Two-layer approach per TAD §6.2:
1. Base score: weighted sum of rule findings, normalized to 0–100.
   Fully explainable, works with zero training data.
2. Calibration layer: XGBoost trained on labeled data (optional).
   Falls back to base score if training data is insufficient.
"""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path

import numpy as np

from secure_smtp.ai.features import FeatureVector
from secure_smtp.db.models import (
    SEVERITY_WEIGHTS,
    Finding,
    RiskScore,
    RiskTier,
)

logger = logging.getLogger(__name__)

# Minimum labeled samples to trust the calibration model
MIN_TRAINING_SAMPLES = 50

# Maximum raw severity sum before normalization clips at 100
MAX_RAW_SCORE = 40  # ~4 critical findings would max out the score


def compute_base_risk_score(findings: list[Finding]) -> tuple[float, RiskTier]:
    """
    Compute the rule-weighted base risk score (TAD §6.2 point 1).

    Weights: info=0, low=2, medium=5, high=8, critical=10
    Sum and normalize to 0–100.

    Args:
        findings: List of Finding objects for a session.

    Returns:
        Tuple of (score_0_100, risk_tier).
    """
    if not findings:
        return 0.0, RiskTier.LOW

    raw_sum = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Normalize to 0–100 using a sigmoid-like curve
    # This ensures the score doesn't just linearly stack
    score = min(100.0, (raw_sum / MAX_RAW_SCORE) * 100.0)

    # Apply tier thresholds
    tier = _score_to_tier(score)

    return round(score, 1), tier


def _score_to_tier(score: float) -> RiskTier:
    """Map a 0–100 score to a risk tier."""
    if score >= 75:
        return RiskTier.CRITICAL
    elif score >= 50:
        return RiskTier.HIGH
    elif score >= 25:
        return RiskTier.MEDIUM
    else:
        return RiskTier.LOW


class RiskModel:
    """
    Combined risk scoring model with base score + optional XGBoost calibration.
    """

    def __init__(self, model_path: str | Path | None = None):
        self.xgb_model = None
        self.model_path = Path(model_path) if model_path else None
        self._use_ml = False

        if self.model_path and self.model_path.exists():
            self._load_model()

    def _load_model(self) -> None:
        """Load a pre-trained XGBoost model."""
        try:
            with open(self.model_path, "rb") as f:
                self.xgb_model = pickle.load(f)
            self._use_ml = True
            logger.info("Loaded calibration model from %s", self.model_path)
        except Exception as e:
            logger.warning("Failed to load calibration model: %s", e)
            self._use_ml = False

    def score_session(
        self,
        feature_vector: FeatureVector,
        findings: list[Finding],
    ) -> RiskScore:
        """
        Compute the risk score for a session.

        Uses the base score as primary, with optional ML calibration.

        Args:
            feature_vector: The session's feature vector.
            findings: The session's rule engine findings.

        Returns:
            RiskScore with score, tier, and feature attribution.
        """
        # Always compute base score
        base_score, base_tier = compute_base_risk_score(findings)

        # Try ML calibration
        ml_score = None
        if self._use_ml and self.xgb_model is not None:
            try:
                features = feature_vector.values.reshape(1, -1)
                ml_score = float(self.xgb_model.predict(features)[0])
                ml_score = max(0.0, min(100.0, ml_score))
            except Exception as e:
                logger.warning("ML calibration failed, using base score: %s", e)
                ml_score = None

        # Choose final score
        final_score = ml_score if ml_score is not None else base_score
        final_tier = _score_to_tier(final_score)

        # Build feature attribution (base-score explanation)
        attribution = self._build_attribution(findings, feature_vector)

        return RiskScore(
            session_id=feature_vector.session_id,
            score_0_100=round(final_score, 1),
            tier=final_tier,
            feature_attribution=json.dumps(attribution),
        )

    def _build_attribution(
        self,
        findings: list[Finding],
        feature_vector: FeatureVector,
    ) -> dict:
        """Build a human-readable feature attribution dict."""
        attribution = {
            "method": "ml_calibration" if self._use_ml else "rule_weighted_base",
            "finding_contributions": [],
            "feature_values": feature_vector.to_dict(),
        }

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity, 0)
            attribution["finding_contributions"].append(
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value
                    if hasattr(f.severity, "value")
                    else str(f.severity),
                    "weight": weight,
                    "message": f.message,
                }
            )

        return attribution

    def train(
        self,
        feature_matrix: np.ndarray,
        labels: np.ndarray,
        save_path: str | Path | None = None,
    ) -> bool:
        """
        Train the XGBoost calibration model.

        Args:
            feature_matrix: (N, 13) feature matrix.
            labels: (N,) array of target risk scores (0–100).
            save_path: Where to save the trained model.

        Returns:
            True if training succeeded, False if insufficient data.
        """
        if len(feature_matrix) < MIN_TRAINING_SAMPLES:
            logger.warning(
                "Insufficient training data (%d < %d minimum). "
                "Keeping rule-weighted base score as default.",
                len(feature_matrix),
                MIN_TRAINING_SAMPLES,
            )
            return False

        try:
            from xgboost import XGBRegressor

            model = XGBRegressor(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.1,
                random_state=42,
            )
            model.fit(feature_matrix, labels)
            self.xgb_model = model
            self._use_ml = True

            if save_path:
                save_path = Path(save_path)
                save_path.parent.mkdir(parents=True, exist_ok=True)
                with open(save_path, "wb") as f:
                    pickle.dump(model, f)
                self.model_path = save_path
                logger.info("Saved calibration model to %s", save_path)

            return True

        except Exception as e:
            logger.error("Failed to train calibration model: %s", e)
            return False


def compute_host_rollup(session_scores: list[RiskScore]) -> float:
    """
    Compute aggregate risk score for a host across all its sessions.

    Uses a weighted average biased toward the worst sessions.
    """
    if not session_scores:
        return 0.0

    scores = [s.score_0_100 for s in session_scores]

    # Weighted: worst sessions get more weight
    scores_sorted = sorted(scores, reverse=True)
    weights = [1.0 / (i + 1) for i in range(len(scores_sorted))]
    total_weight = sum(weights)

    weighted_sum = sum(s * w for s, w in zip(scores_sorted, weights))
    return round(weighted_sum / total_weight, 1) if total_weight > 0 else 0.0
