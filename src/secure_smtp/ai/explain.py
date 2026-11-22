"""
SHAP explainability wiring — Stage 5.

Provides feature attribution for risk scores using SHAP
(SHapley Additive exPlanations). Falls back to rule-based
attribution when no ML model is available.
Per TAD §6.2 / FR-18.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import numpy as np

from secure_smtp.ai.features import FEATURE_NAMES, FeatureVector
from secure_smtp.db.models import SEVERITY_WEIGHTS, Finding, RiskScore

logger = logging.getLogger(__name__)


def compute_shap_explanation(
    model: Any,
    feature_vector: FeatureVector,
) -> dict[str, float]:
    """
    Compute SHAP feature attribution for a risk score.

    Uses TreeExplainer for tree-based models (XGBoost, LightGBM)
    or falls back to a feature importance-based approximation.

    Args:
        model: The trained ML model (XGBoost/LightGBM).
        feature_vector: The session's feature vector.

    Returns:
        Dictionary mapping feature names to SHAP values.
    """
    try:
        import shap

        explainer = shap.TreeExplainer(model)
        features = feature_vector.values.reshape(1, -1)
        shap_values = explainer.shap_values(features)

        if isinstance(shap_values, list):
            shap_values = shap_values[0]

        # Map to feature names
        shap_dict = {}
        for i, name in enumerate(FEATURE_NAMES):
            if i < len(shap_values[0]):
                shap_dict[name] = round(float(shap_values[0][i]), 4)

        return shap_dict

    except Exception as e:
        logger.debug("SHAP computation failed, using feature importance fallback: %s", e)
        return _fallback_attribution(feature_vector)


def _fallback_attribution(feature_vector: FeatureVector) -> dict[str, float]:
    """
    Compute a simple feature attribution when SHAP isn't available.

    Uses the absolute feature value as a proxy for importance,
    normalized to sum to 1.0.
    """
    values = np.abs(feature_vector.values)
    total = values.sum()

    if total == 0:
        return {name: 0.0 for name in FEATURE_NAMES}

    normalized = values / total
    return {name: round(float(val), 4) for name, val in zip(FEATURE_NAMES, normalized)}


def compute_rule_based_explanation(
    findings: list[Finding],
    feature_vector: FeatureVector,
) -> dict:
    """
    Compute an explainable attribution from rule-engine findings.

    This is the primary explanation method that works without any ML model.
    Every score is fully traceable to the underlying facts/features.

    Args:
        findings: Rule engine findings for the session.
        feature_vector: The session's feature vector.

    Returns:
        Human-readable explanation dictionary.
    """
    explanation = {
        "method": "rule_weighted",
        "total_findings": len(findings),
        "contributions": [],
        "feature_summary": {},
    }

    total_weight = 0
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
        total_weight += weight
        explanation["contributions"].append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value
                if hasattr(finding.severity, "value")
                else str(finding.severity),
                "weight": weight,
                "percentage": 0.0,  # Will be filled in below
                "message": finding.message,
                "recommendation": finding.recommendation_text,
            }
        )

    # Calculate percentages
    if total_weight > 0:
        for contrib in explanation["contributions"]:
            contrib["percentage"] = round((contrib["weight"] / total_weight) * 100, 1)

    # Feature summary — key facts about the session
    fv_dict = feature_vector.to_dict()
    tls_version_map = {0: "None", 1: "SSLv3", 2: "TLS1.0", 3: "TLS1.1", 4: "TLS1.2", 5: "TLS1.3"}
    tls_ordinal = int(fv_dict.get("tls_version_ordinal", 0))

    explanation["feature_summary"] = {
        "tls_version": tls_version_map.get(tls_ordinal, "Unknown"),
        "cipher_strength": f"{fv_dict.get('cipher_strength_score', 0)}/10",
        "forward_secrecy": bool(fv_dict.get("forward_secrecy", 0)),
        "cert_key_length": int(fv_dict.get("cert_key_length", 0)),
        "cert_self_signed": bool(fv_dict.get("cert_self_signed", 0)),
        "days_to_cert_expiry": int(fv_dict.get("days_to_cert_expiry", 0)),
        "has_tls": bool(fv_dict.get("has_tls", 0)),
    }

    return explanation


def enrich_risk_score_with_explanation(
    risk_score: RiskScore,
    findings: list[Finding],
    feature_vector: FeatureVector,
    model: Any = None,
) -> RiskScore:
    """
    Add SHAP or rule-based explanation to a risk score.

    Args:
        risk_score: The risk score to enrich.
        findings: Rule engine findings.
        feature_vector: The session's feature vector.
        model: Optional ML model for SHAP explanations.

    Returns:
        The same RiskScore with updated feature_attribution.
    """
    if model is not None:
        shap_values = compute_shap_explanation(model, feature_vector)
        explanation = {
            "method": "shap",
            "shap_values": shap_values,
            "rule_explanation": compute_rule_based_explanation(findings, feature_vector),
        }
    else:
        explanation = compute_rule_based_explanation(findings, feature_vector)

    risk_score.feature_attribution = json.dumps(explanation)
    return risk_score
