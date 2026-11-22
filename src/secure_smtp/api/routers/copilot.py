"""
AI Security Copilot & Automated Remediation API Router.

Provides Generative AI incident briefings, mail daemon configuration remediation stanzas,
Isolation Forest anomaly detection metrics, and Post-Quantum Cryptography (PQC) readiness.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from secure_smtp.ai.copilot import (
    ask_copilot,
    generate_incident_briefing,
    generate_server_remediation,
)
from secure_smtp.api.auth import Principal, verify_api_key, visible_scope


def _get_sessions_col():
    from secure_smtp.api import main

    return main.get_sessions_col()


logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])


class RemediateRequest(BaseModel):
    server_type: str = Field(default="postfix", max_length=64)


class AskCopilotRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


class GlobalAskCopilotRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)
    session_id: int | None = None


@router.post("/api/sessions/{session_id}/copilot/remediate")
def copilot_remediate(
    session_id: int,
    req: RemediateRequest = RemediateRequest(),
    principal: Principal = Depends(verify_api_key),
) -> dict:
    """Generate production-ready mail server configuration to fix detected weaknesses."""
    sessions_col = _get_sessions_col()
    session = sessions_col.find_one(visible_scope(principal, {"id": session_id}))
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    return generate_server_remediation(session, findings, req.server_type)


@router.post("/api/sessions/{session_id}/copilot/briefing")
def copilot_briefing(session_id: int, principal: Principal = Depends(verify_api_key)) -> dict:
    """Generate an executive-level CISO incident briefing memo."""
    sessions_col = _get_sessions_col()
    session = sessions_col.find_one(visible_scope(principal, {"id": session_id}))
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    risk_info = session.get("risk_score") or {}
    score = risk_info.get("score_0_100", 0.0)
    return generate_incident_briefing(session, findings, score)


@router.post("/api/sessions/{session_id}/copilot/ask")
def copilot_ask(
    session_id: int, req: AskCopilotRequest, principal: Principal = Depends(verify_api_key)
) -> dict:
    """Ask the AI Copilot any question about this session's security posture."""
    sessions_col = _get_sessions_col()
    session = sessions_col.find_one(visible_scope(principal, {"id": session_id}))
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    return ask_copilot(session, findings, req.query)


@router.post("/api/ai/copilot/ask")
def global_copilot_ask(
    req: GlobalAskCopilotRequest, principal: Principal = Depends(verify_api_key)
) -> dict:
    """Ask the AI Copilot any security or hardening question across the fleet."""
    sessions_col = _get_sessions_col()
    session = None
    if req.session_id:
        session = sessions_col.find_one(visible_scope(principal, {"id": req.session_id}))
    if req.session_id and not session:
        raise HTTPException(404, "Session not found")
    if not session:
        session = sessions_col.find_one(
            visible_scope(principal), sort=[("risk_score.score_0_100", -1)]
        ) or sessions_col.find_one(visible_scope(principal), sort=[("id", -1)])
    if not session:
        raise HTTPException(404, "No observed session is available for this organization")
    findings = session.get("findings", [])
    return ask_copilot(session, findings, req.query)


@router.get("/api/ai/overview")
def global_ai_overview(principal: Principal = Depends(verify_api_key)) -> dict:
    """Get high-level AI security analytics including Isolation Forest anomaly baselines and PQC metrics."""
    sessions_col = _get_sessions_col()
    total_sessions = sessions_col.count_documents(visible_scope(principal))
    anomalous_count = sessions_col.count_documents(
        visible_scope(principal, {"anomaly_score.is_anomalous": True})
    )
    engine_name = (
        "External AI configured; individual responses identify their source"
        if (os.environ.get("GEMINI_API_KEY") or os.environ.get("SECURE_SMTP_GEMINI_KEY"))
        else "Rule-based templates"
    )

    return {
        "engine": engine_name,
        "isolation_forest": {
            "status": "batch observations only" if total_sessions else "unavailable",
            "model": "IsolationForest(contamination=0.08, n_estimators=100)",
            "anomalous_sessions": anomalous_count,
            "conformity_rate": f"{max(0, 100 - round((anomalous_count / total_sessions) * 100, 1))}%"
            if total_sessions
            else None,
        },
        "explainable_ai": {
            "method": "Session-specific attribution; no fleet-wide feature weights computed",
            "primary_features": [],
        },
        "post_quantum_readiness": {
            "risk_status": "Not assessed",
            "vulnerable_sessions": None,
            "total_evaluated": 0,
            "pqc_score": None,
            "recommendation": "Passive TLS observations alone do not establish post-quantum readiness.",
        },
    }
