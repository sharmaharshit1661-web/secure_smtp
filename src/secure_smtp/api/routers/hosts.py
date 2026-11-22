"""
Host Inventory API Router.

Provides host-level posture rollups, risk ranking, and session breakdowns.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pymongo import DESCENDING

from secure_smtp.api.auth import Principal, verify_api_key, visible_scope
from secure_smtp.db.mongodb import get_hosts_col, get_sessions_col

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hosts", tags=["Hosts"], dependencies=[Depends(verify_api_key)])


@router.get("")
async def list_hosts(principal: Principal = Depends(verify_api_key)) -> list[dict]:
    """List all evaluated mail hosts sorted by aggregate risk score descending."""
    hosts_col = get_hosts_col()
    hosts = list(hosts_col.find(visible_scope(principal), {"_id": 0}).sort("aggregate_risk_score", DESCENDING))
    return [
        {
            "host_id": h["id"],
            "ip": h["ip_or_hostname"],
            "aggregate_risk_score": h.get("aggregate_risk_score", 0.0),
            "session_count": h.get("session_count", 0),
        }
        for h in hosts
    ]


@router.get("/{host_id}")
async def get_host_detail(host_id: int, principal: Principal = Depends(verify_api_key)) -> dict:
    """Get detailed host metadata including complete session history."""
    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    host = hosts_col.find_one(visible_scope(principal, {"id": host_id}), {"_id": 0})
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    sessions = list(sessions_col.find(visible_scope(principal, {"host_id": host_id}), {"_id": 0}))

    session_list = []
    for s in sessions:
        risk = s.get("risk_score") or {}
        proto = s.get("protocol", "unknown")
        proto_val = proto.value if hasattr(proto, "value") else str(proto)

        tls = s.get("tls_mode", "none")
        tls_val = tls.value if hasattr(tls, "value") else str(tls)

        session_list.append({
            "session_id": s["id"],
            "src_ip": s["src_ip"],
            "dst_ip": s["dst_ip"],
            "src_port": s["src_port"],
            "dst_port": s["dst_port"],
            "protocol": proto_val,
            "tls_mode": tls_val,
            "risk_score": risk.get("score_0_100", 0.0) if risk else None,
            "risk_tier": risk.get("tier", "low") if risk else None,
        })

    return {
        "host_id": host["id"],
        "ip": host["ip_or_hostname"],
        "aggregate_risk_score": host.get("aggregate_risk_score", 0.0),
        "session_count": host.get("session_count", len(sessions)),
        "sessions": session_list,
    }
