"""
Live Mail Lab & Real-Time WebSocket Streaming API Router.

Controls the embedded multi-port mail lab, triggers attack scenarios, and streams
cryptographic forensic events to connected web consoles.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from secure_smtp.api.auth import (
    Principal,
    require_admin,
    require_lab_admin,
    scope,
    verify_api_key,
    verify_token,
)
from secure_smtp.api.broker import get_connection_manager
from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Live Monitoring"])


class CustomMailDispatchRequest(BaseModel):
    server_ip: str | None = None
    port: int = 2525
    scenario: str = "plaintext"
    sender: str = "alice@client-device.local"
    recipient: str = "bob@securesmtp.local"
    subject: str = "Live Web Client Mail"
    body: str = "Confidential telemetry packet transmitted across network."
    client_name: str = "Interactive Web Client"


@router.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket) -> None:
    """Real-time event stream for incoming packet analyses, simulated sessions, and security alerts."""
    settings = get_settings()
    origin = websocket.headers.get("origin")
    if not origin:
        await websocket.close(code=4403)
        return

    allowed = set()
    cors_orig = getattr(settings, "cors_origins", [])
    if isinstance(cors_orig, list):
        allowed.update(cors_orig)
    elif cors_orig:
        allowed.add(cors_orig)

    clerk_parties = getattr(settings, "clerk_authorized_parties", [])
    if isinstance(clerk_parties, list):
        allowed.update(clerk_parties)
    elif clerk_parties:
        allowed.add(clerk_parties)

    is_allowed = (
        "*" in allowed
        or origin in allowed
        or origin.endswith(".vercel.app")
        or "localhost" in origin
        or "127.0.0.1" in origin
    )

    if not is_allowed:
        await websocket.close(code=4403)
        return
    manager = get_connection_manager()
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        if len(message) > 16400:
            raise ValueError("Authentication message too large")
        import json

        payload = json.loads(message)
        principal = await run_in_threadpool(verify_token, payload.get("token", ""))
        await manager.connect(websocket, principal, accepted=True)
        await websocket.send_json({"event": "AUTHENTICATED"})
        while time.time() < principal.expires_at:
            data = await asyncio.wait_for(
                websocket.receive_text(), timeout=max(0.01, principal.expires_at - time.time())
            )
            if data == "ping":
                await websocket.send_text("pong")
        await websocket.close(code=4401)
    except WebSocketDisconnect:
        pass
    except (TimeoutError, HTTPException, ValueError, TypeError, AttributeError):
        await websocket.close(code=4401)
    finally:
        manager.disconnect(websocket)


@router.get("/api/live/status", dependencies=[Depends(verify_api_key)])
async def get_live_status() -> dict:
    """Get status of the live test lab and streaming server."""
    from secure_smtp.live.mail_server import get_live_lab, get_local_ip

    lab = get_live_lab()
    manager = get_connection_manager()
    return {
        "status": "active" if lab.is_running else "ready",
        "is_running": lab.is_running,
        "lan_ip": get_local_ip(),
        "ports": {
            "plaintext": 2525,
            "tls_modern": 2526,
            "tls_vulnerable": 2527,
            "stripping": 2528,
        },
        "websocket_subscribers": len(manager.active_connections),
    }


@router.post("/api/live/start-lab", dependencies=[Depends(require_lab_admin)])
async def start_lab_endpoint() -> dict:
    """Start the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if not lab.is_running:
        ports = await lab.start()
        return {"status": "started", "ports": ports}
    return {"status": "already_running"}


@router.post("/api/live/stop-lab", dependencies=[Depends(require_lab_admin)])
async def stop_lab_endpoint() -> dict:
    """Stop the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if lab.is_running:
        await lab.stop()
        return {"status": "stopped"}
    return {"status": "already_stopped"}


@router.post("/api/live/simulate/{scenario}", dependencies=[Depends(require_lab_admin)])
async def simulate_scenario_endpoint(scenario: str) -> dict:
    """Trigger a live email traffic simulation and broadcast the forensic results in real-time."""
    from secure_smtp.live.generator import simulate_live_session

    try:
        session_event = await simulate_live_session(scenario)
        return session_event
    except Exception as e:
        logger.error("Simulation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/live/clear-history", dependencies=[Depends(verify_api_key)])
async def clear_live_history(principal: Principal = Depends(require_admin)) -> dict:
    """Clear all historical sessions and reset database for a fresh demonstration."""
    from secure_smtp.db.mongodb import get_hosts_col, get_sessions_col

    sessions_col = get_sessions_col()
    hosts_col = get_hosts_col()

    s_res = sessions_col.delete_many(scope(principal, {"source_kind": "controlled_lab"}))
    deleted_hosts = 0
    for host in hosts_col.find(scope(principal, {"source_kind": "controlled_lab"})):
        if not sessions_col.find_one(scope(principal, {"host_id": host["id"]})):
            deleted_hosts += hosts_col.delete_one(
                scope(principal, {"id": host["id"]})
            ).deleted_count

    # Broadcast reset event over WebSocket so all connected clients clear live tickers
    manager = get_connection_manager()
    await manager.broadcast(
        {
            "event": "DATABASE_RESET",
            "org_id": principal.org_id,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )

    return {
        "status": "cleared",
        "deleted_sessions": s_res.deleted_count,
        "deleted_hosts": deleted_hosts,
        "message": "Database reset to clean slate. Ready for live mail injection.",
    }


@router.post("/api/live/dispatch-custom", dependencies=[Depends(require_lab_admin)])
async def dispatch_custom_mail(req: CustomMailDispatchRequest) -> dict:
    """Execute a real-time SMTP client connection and return the complete socket transcript."""
    from secure_smtp.live.client_dispatcher import execute_client_dispatch_async

    host = req.server_ip or "127.0.0.1"
    if host != "127.0.0.1" or req.port not in (2525, 2526, 2527, 2528):
        raise HTTPException(403, "Only the local controlled lab is an allowed destination")
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
