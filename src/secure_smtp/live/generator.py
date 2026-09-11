"""
Live Traffic Generator & Simulation Dispatcher.

Connects to the Live Mail Lab or injects synthetic traffic through the Secure SMTP pipeline,
persisting findings in MongoDB and broadcasting real-time events via WebSockets.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secure_smtp.api.main import _run_analysis, get_connection_manager
from secure_smtp.db.mongodb import get_hosts_col, get_sessions_col

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "pcaps"

SCENARIO_MAP = {
    "starttls_stripped": {
        "pcap": "smtp_starttls_stripped.pcap",
        "title": "STARTTLS Stripping Downgrade Attack",
        "severity": "CRITICAL",
        "port": 2528,
    },
    "weak_cipher": {
        "pcap": "smtp_tls10_rc4.pcap",
        "title": "Deprecated TLS 1.0 + RC4 Cipher",
        "severity": "HIGH",
        "port": 2527,
    },
    "expired_cert": {
        "pcap": "smtp_expired_cert.pcap",
        "title": "Expired X.509 Certificate Chain",
        "severity": "CRITICAL",
        "port": 2527,
    },
    "tls13_good": {
        "pcap": "smtp_tls13_good.pcap",
        "title": "Modern Hardened TLS 1.3 Baseline",
        "severity": "CLEAN",
        "port": 2526,
    },
    "plaintext": {
        "pcap": "smtp_plaintext.pcap",
        "title": "Plaintext Port 25 Leakage (No TLS)",
        "severity": "CRITICAL",
        "port": 2525,
    },
}


async def simulate_live_session(scenario_id: str) -> dict[str, Any]:
    """
    Run an on-demand live traffic simulation, process it through the forensic pipeline,
    and broadcast the new session event over WebSockets.
    """
    scenario = SCENARIO_MAP.get(scenario_id, SCENARIO_MAP["starttls_stripped"])
    pcap_file = FIXTURES_DIR / scenario["pcap"]

    if not pcap_file.exists():
        raise FileNotFoundError(f"Scenario PCAP fixture not found: {pcap_file}")

    job_id = f"sim_{uuid.uuid4().hex[:8]}"

    # Run analysis pipeline
    _run_analysis(job_id, str(pcap_file))

    # Retrieve newly created session from MongoDB
    sessions_col = get_sessions_col()
    hosts_col = get_hosts_col()

    session_doc = sessions_col.find_one(
        {"pcap_source": scenario["pcap"]},
        sort=[("id", -1)],
    )

    if not session_doc:
        session_doc = sessions_col.find_one(sort=[("id", -1)])

    if not session_doc:
        raise RuntimeError("Failed to retrieve generated session from MongoDB")

    session_id = session_doc.get("id")
    host_id = session_doc.get("host_id")
    host_doc = hosts_col.find_one({"id": host_id}) if host_id else None
    dst_ip = session_doc.get("dst_ip", "127.0.0.1")

    risk_data = session_doc.get("risk_score") or {}
    score = risk_data.get("score_0_100", 0.0)
    tier = risk_data.get("tier", "low")

    payload = {
        "event": "NEW_SESSION",
        "timestamp": datetime.now(UTC).isoformat(),
        "scenario": scenario["title"],
        "session_id": session_id,
        "host_id": host_id,
        "src_ip": session_doc.get("src_ip"),
        "dst_ip": dst_ip,
        "src_port": session_doc.get("src_port"),
        "dst_port": session_doc.get("dst_port") or scenario["port"],
        "protocol": str(session_doc.get("protocol", "SMTP")).upper(),
        "tls_mode": str(session_doc.get("tls_mode", "none")).upper(),
        "risk_score": score,
        "risk_tier": tier,
        "findings_count": len(session_doc.get("findings", [])),
        "findings": session_doc.get("findings", []),
    }

    # Broadcast to connected WebSockets
    manager = get_connection_manager()
    await manager.broadcast(payload)

    logger.info("Simulated live session #%s for %s (%s)", session_id, scenario["title"], score)
    return payload
