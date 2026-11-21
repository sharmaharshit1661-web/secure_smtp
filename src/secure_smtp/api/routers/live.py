"""
Live Mail Lab & Real-Time WebSocket Streaming API Router.

Controls the embedded multi-port mail lab, triggers attack scenarios, and streams
cryptographic forensic events to connected web consoles.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, field_validator

from secure_smtp.api.auth import verify_api_key
from secure_smtp.api.broker import get_connection_manager
from secure_smtp.api.ratelimit import rate_limit
from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Live Monitoring"])



def require_lab_enabled():
    if not get_settings().enable_live_lab:
        raise HTTPException(403, "Mail lab actions are disabled")


ALLOWED_MAIL_PORTS = {25, 465, 587, 2525, 2526, 2527, 2528}
BLOCKED_HOST_PREFIXES = ("169.254.", "metadata.", "127.0.0.1.nip.io")


class CustomMailDispatchRequest(BaseModel):
    server_ip: str | None = None
    port: int = 2525
    scenario: str = "plaintext"
    sender: str = "alice@client-device.local"
    recipient: str = "bob@securesmtp.local"
    subject: str = "Live Web Client Mail"
    body: str = "Confidential telemetry packet transmitted across network."
    client_name: str = "Interactive Web Client"

    @field_validator("sender", "recipient", "subject", "client_name")
    @classmethod
    def validate_no_crlf(cls, v: str) -> str:
        """Prevent SMTP Header Injection and CRLF injection vulnerabilities."""
        if "\r" in v or "\n" in v:
            raise ValueError("CRLF characters (\\r, \\n) are forbidden to prevent SMTP header injection.")
        return v.strip()

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Enforce strict port whitelist to mitigate SSRF port-scanning attacks."""
        if v not in ALLOWED_MAIL_PORTS:
            raise ValueError(f"Port {v} is not permitted. Permitted SMTP ports: {sorted(ALLOWED_MAIL_PORTS)}")
        return v

    @field_validator("server_ip")
    @classmethod
    def validate_server_ip(cls, v: str | None) -> str | None:
        """Prevent SSRF attacks against cloud provider instance metadata endpoints."""
        if not v:
            return v
        try:
            address = ipaddress.ip_address(v.strip())
        except ValueError:
            raise ValueError("Use an explicitly permitted IP address; hostnames are not accepted")
        allowed = {ipaddress.ip_address(ip.strip()) for ip in get_settings().dispatch_allowed_ips.split(",") if ip.strip()}
        if address.is_link_local or address.is_multicast or address.is_unspecified or address not in allowed:
            raise ValueError("Target IP is not in the dispatch allowlist")
        return str(address)



@router.websocket("/ws/live")
async def websocket_live_endpoint(
    websocket: WebSocket,
    token: str | None = Query(None),
) -> None:
    """Real-time event stream for incoming packet analyses, simulated sessions, and security alerts."""
    settings = get_settings()

    from secure_smtp.api.sessions_auth import check_origin, consume_ticket
    try:
        if websocket.headers.get("origin"):
            check_origin(websocket.headers["origin"])
        identity = consume_ticket(token)
        # Header keys are for non-browser clients; never expose keys in URLs.
        machine_key = websocket.headers.get("x-api-key")
        expected = settings.api_key.strip()
        machine_valid = bool(machine_key and expected and secrets.compare_digest(machine_key, expected))
        if settings.is_production and (expected == "securesmtp_live_secret_key" or len(expected) < 32):
            machine_valid = False
        if not identity and not machine_valid:
            raise HTTPException(401, "Authentication required")
    except HTTPException:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized")
        return

    manager = get_connection_manager()
    await manager.connect(websocket)
    deadline = time.monotonic() + 60
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            data = await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
            if data == "ping":
                await websocket.send_text("pong")
    except (TimeoutError, WebSocketDisconnect):
        pass
    finally:
        manager.disconnect(websocket)
        try:
            await websocket.close()
        except RuntimeError:
            pass


@router.get("/api/live/status", dependencies=[Depends(verify_api_key)])
async def get_live_status() -> dict:
    """Get status of the live test lab and streaming server."""
    from secure_smtp.live.mail_server import get_live_lab, get_local_ip

    lab = get_live_lab()
    manager = get_connection_manager()
    return {
        "status": "active" if lab.is_running else "ready",
        "is_running": lab.is_running,
        "max_upload_size_mb": get_settings().max_upload_size_mb,
        "lan_ip": get_local_ip(),
        "ports": {
            "plaintext": 2525,
            "tls_modern": 2526,
            "tls_vulnerable": 2527,
            "stripping": 2528,
        },
        "websocket_subscribers": len(manager.active_connections),
    }


@router.post("/api/live/start-lab", dependencies=[Depends(verify_api_key), Depends(require_lab_enabled)])
async def start_lab_endpoint() -> dict:
    """Start the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if not lab.is_running:
        ports = await lab.start()
        return {"status": "started", "ports": ports}
    return {"status": "already_running"}


@router.post("/api/live/stop-lab", dependencies=[Depends(verify_api_key)])
async def stop_lab_endpoint() -> dict:
    """Stop the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if lab.is_running:
        await lab.stop()
        return {"status": "stopped"}
    return {"status": "already_stopped"}


@router.post("/api/live/simulate/{scenario}", dependencies=[Depends(verify_api_key), Depends(require_lab_enabled)])
async def simulate_scenario_endpoint(scenario: str) -> dict:
    """Trigger a live email traffic simulation and broadcast the forensic results in real-time."""
    from secure_smtp.live.generator import simulate_live_session

    try:
        session_event = await simulate_live_session(scenario)
        return session_event
    except Exception as e:
        logger.error("Simulation failed: %s", e)
        raise HTTPException(status_code=500, detail="Simulation failed; check server logs")


@router.post(
    "/api/live/clear-history",
    dependencies=[
        Depends(verify_api_key),
        Depends(require_lab_enabled),
        Depends(rate_limit(max_requests=5, window_seconds=60, scope="clear_history")),
    ],
)
async def clear_live_history() -> dict:
    """Clear all historical sessions and reset database for a fresh demonstration."""
    from secure_smtp.db.mongodb import get_hosts_col, get_sessions_col

    sessions_col = get_sessions_col()
    hosts_col = get_hosts_col()

    s_res = sessions_col.delete_many({})
    h_res = hosts_col.delete_many({})

    # Broadcast reset event over WebSocket so all connected clients clear live tickers
    manager = get_connection_manager()
    await manager.broadcast({
        "event": "DATABASE_RESET",
        "timestamp": datetime.now(UTC).isoformat(),
    })

    return {
        "status": "cleared",
        "deleted_sessions": s_res.deleted_count,
        "deleted_hosts": h_res.deleted_count,
        "message": "Database reset to clean slate. Ready for live mail injection.",
    }


@router.post(
    "/api/live/dispatch-custom",
    dependencies=[
        Depends(verify_api_key),
        Depends(require_lab_enabled),
        Depends(rate_limit(max_requests=30, window_seconds=60, scope="dispatch_custom")),
    ],
)
async def dispatch_custom_mail(req: CustomMailDispatchRequest) -> dict:
    """Execute a real-time SMTP client connection and return the complete socket transcript."""
    from secure_smtp.live.client_dispatcher import execute_client_dispatch_async

    host = req.server_ip or "127.0.0.1"
    result = await execute_client_dispatch_async(
        host=host,
        port=req.port,
        scenario=req.scenario,
        sender=req.sender,
        recipient=req.recipient,
        subject=req.subject,
        body=req.body,
        client_name=req.client_name,
    )
    return result
