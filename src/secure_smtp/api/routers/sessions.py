"""
Session Explorer API Router.

Provides session-level cryptographic inspection, rule findings, and SHAP feature attribution.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pymongo import DESCENDING

from secure_smtp.api.auth import verify_api_key
from secure_smtp.db.mongodb import get_sessions_col

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sessions", tags=["Sessions"], dependencies=[Depends(verify_api_key)])


@router.get("")
async def list_sessions(
    limit: int = Query(100, ge=1, le=1000, description="Max session records to return (1-1000)"),
) -> list[dict]:
    """List recent sessions across all hosts for fleet-wide telemetry."""
    sessions_col = get_sessions_col()
    sessions = list(sessions_col.find({}, {"_id": 0}).sort("id", DESCENDING).limit(limit))
    return [
        {
            "id": s["id"],
            "host_id": s.get("host_id"),
            "src_ip": s.get("src_ip"),
            "dst_ip": s.get("dst_ip"),
            "src_port": s.get("src_port"),
            "dst_port": s.get("dst_port"),
            "protocol": s.get("protocol").value if hasattr(s.get("protocol"), "value") else str(s.get("protocol", "smtp")),
            "tls_mode": s.get("tls_mode").value if hasattr(s.get("tls_mode"), "value") else str(s.get("tls_mode", "none")),
            "risk_score": (s.get("risk_score") or {}).get("score_0_100", 0.0),
            "risk_tier": (s.get("risk_score") or {}).get("tier", "low"),
            "findings": [
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "message": f.get("message"),
                }
                for f in s.get("findings", []) if isinstance(f, dict)
            ],
            "tls_version": (s.get("handshake") or {}).get("tls_version_negotiated"),
            "cipher_suite": (s.get("handshake") or {}).get("cipher_suite_negotiated"),
            "forward_secrecy": (s.get("handshake") or {}).get("forward_secrecy", False),
        }
        for s in sessions
    ]


@router.get("/{session_id}")
async def get_session_detail(session_id: int) -> dict:
    """Get full session forensic detail including certificates, findings, and risk score."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    handshake = session.get("handshake")
    certificates = session.get("certificates", [])
    findings = session.get("findings", [])
    risk_score = session.get("risk_score")
    anomaly_score = session.get("anomaly_score")

    proto = session.get("protocol", "unknown")
    proto_val = proto.value if hasattr(proto, "value") else str(proto)

    tls = session.get("tls_mode", "none")
    tls_val = tls.value if hasattr(tls, "value") else str(tls)

    result = {
        "id": session["id"],
        "pcap_source": session.get("pcap_source", ""),
        "src_ip": session["src_ip"],
        "dst_ip": session["dst_ip"],
        "src_port": session["src_port"],
        "dst_port": session["dst_port"],
        "protocol": proto_val,
        "tls_mode": tls_val,
        "starttls_advertised": session.get("starttls_advertised", False),
        "starttls_completed": session.get("starttls_completed", False),
    }

    if handshake:
        kex = handshake.get("key_exchange_type", "unknown")
        kex_val = kex.value if hasattr(kex, "value") else str(kex)
        result["handshake"] = {
            "tls_version_negotiated": handshake.get("tls_version_negotiated", ""),
            "cipher_suite_negotiated": handshake.get("cipher_suite_negotiated", ""),
            "key_exchange_type": kex_val,
            "forward_secrecy": handshake.get("forward_secrecy", False),
            "ja3": handshake.get("ja3", ""),
            "ja3s": handshake.get("ja3s", ""),
            "ja4": handshake.get("ja4", ""),
            "ja4s": handshake.get("ja4s", ""),
            "visibility_limited": handshake.get("visibility_limited", False),
        }

    result["certificates"] = [
        {
            "chain_position": c.get("chain_position", 0),
            "subject": c.get("subject", ""),
            "issuer": c.get("issuer", ""),
            "not_before": c.get("not_before"),
            "not_after": c.get("not_after"),
            "public_key_algorithm": c.get("public_key_algorithm", ""),
            "key_length_bits": c.get("key_length_bits", 0),
            "signature_algorithm": c.get("signature_algorithm", ""),
            "self_signed": c.get("self_signed", False),
            "chain_valid": c.get("chain_valid", True),
        }
        for c in certificates
    ]

    result["findings"] = [
        {
            "rule_id": f.get("rule_id", ""),
            "severity": f.get("severity", "info"),
            "message": f.get("message", ""),
            "recommendation": f.get("recommendation_text") or f.get("recommendation", ""),
        }
        for f in findings
    ]

    if risk_score:
        expl = risk_score.get("feature_attribution", "{}")
        if isinstance(expl, str):
            try:
                expl = json.loads(expl)
            except Exception:
                expl = {}
        result["risk_score"] = {
            "score": risk_score.get("score_0_100", 0.0),
            "tier": risk_score.get("tier", "low"),
            "explanation": expl,
        }

    if anomaly_score:
        result["anomaly_score"] = {
            "score": anomaly_score.get("anomaly_score", 0.0),
            "is_anomalous": anomaly_score.get("is_anomalous", False),
            "baseline": anomaly_score.get("baseline_reference", "global"),
        }

    return result


@router.get("/{session_id}/explain")
async def get_session_explanation(session_id: int) -> dict:
    """Get SHAP feature attribution for a session's risk score."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id}, {"_id": 0})
    if not session or not session.get("risk_score"):
        raise HTTPException(status_code=404, detail="Risk score not found for session")

    risk_score = session["risk_score"]
    expl = risk_score.get("feature_attribution", "{}")
    if isinstance(expl, str):
        try:
            expl = json.loads(expl)
        except Exception:
            expl = {}

    return {
        "session_id": session_id,
        "score": risk_score.get("score_0_100", 0.0),
        "tier": risk_score.get("tier", "low"),
        "explanation": expl,
    }
