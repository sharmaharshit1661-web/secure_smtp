"""
AI Risk Attribution, Anomaly Detection & Copilot Package.

Provides:
- Machine Learning risk attribution (XGBoost / Random Forest)
- Unsupervised anomaly detection (Isolation Forest)
- SHAP feature explainability
- Generative AI incident briefings and mail daemon remediation synthesis
"""

from __future__ import annotations

from secure_smtp.ai.anomaly_model import AnomalyDetector
from secure_smtp.ai.copilot import (
    ask_copilot,
    generate_incident_briefing,
    generate_server_remediation,
)
from secure_smtp.ai.explain import (
    compute_rule_based_explanation,
    compute_shap_explanation,
    enrich_risk_score_with_explanation,
)
from secure_smtp.ai.features import FeatureVector, build_feature_vector
from secure_smtp.ai.risk_model import RiskModel, compute_host_rollup

__all__ = [
    "AnomalyDetector",
    "RiskModel",
    "compute_host_rollup",
    "FeatureVector",
    "build_feature_vector",
    "compute_shap_explanation",
    "compute_rule_based_explanation",
    "enrich_risk_score_with_explanation",
    "ask_copilot",
    "generate_incident_briefing",
    "generate_server_remediation",
]
