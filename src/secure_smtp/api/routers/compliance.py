"""
Regulatory & Standards Compliance API Router.

Evaluates fleet and session compliance against NIST SP 800-52r2, PCI-DSS 4.0, HIPAA, and MTA-STS.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from secure_smtp.api.auth import Principal, verify_api_key, visible_scope
from secure_smtp.compliance.frameworks import evaluate_fleet_compliance, evaluate_session_compliance
from secure_smtp.db.mongodb import get_sessions_col

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Compliance"], dependencies=[Depends(verify_api_key)])


@router.get("/api/compliance/summary")
def get_compliance_summary(principal: Principal = Depends(verify_api_key)) -> dict:
    """Evaluate fleet-wide regulatory compliance (NIST SP 800-52, PCI-DSS, MTA-STS)."""
    sessions_col = get_sessions_col()
    sessions = list(sessions_col.find(visible_scope(principal)))
    return evaluate_fleet_compliance(sessions)


@router.get("/api/sessions/{session_id}/compliance")
def get_session_compliance(session_id: int, principal: Principal = Depends(verify_api_key)) -> dict:
    """Evaluate specific session compliance against NIST, PCI-DSS, and MTA-STS."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one(visible_scope(principal, {"id": session_id}))
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return evaluate_session_compliance(session)
