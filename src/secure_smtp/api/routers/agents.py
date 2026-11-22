"""Agent management and metadata ingestion use separate user/agent credentials."""

import threading
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from secure_smtp.api.auth import Principal, http_bearer, require_admin, scope, verify_api_key
from secure_smtp.api.broker import get_connection_manager
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database, serialize_doc
from secure_smtp.monitoring.schema import Heartbeat, ObservationBatch
from secure_smtp.monitoring.service import audit, authenticate_agent, create_agent, ingest_batch

router = APIRouter(prefix="/api/agents", tags=["Agents"])
_ingestion_slot = threading.Lock()


class AgentName(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80, pattern=r"^[\w .-]+$")


async def agent_identity(
    request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer)
):
    settings = get_settings()
    local = request.client and request.client.host in ("127.0.0.1", "::1", "testclient")
    if request.url.scheme != "https" and not (settings.agent_allow_insecure_local and local):
        raise HTTPException(403, "Agent ingestion requires HTTPS")
    if not credentials:
        raise HTTPException(401, "Agent credential required")
    return await run_in_threadpool(authenticate_agent, credentials.credentials)


@router.get("")
def list_agents(principal: Principal = Depends(verify_api_key)):
    result = []
    for agent in get_database().agents.find(scope(principal), {"_id": 0, "secret_hash": 0}):
        last_seen = agent.get("last_seen")
        seconds = (
            (datetime.now(UTC) - last_seen.replace(tzinfo=UTC)).total_seconds()
            if last_seen
            else None
        )
        agent["status"] = (
            "revoked"
            if agent["revoked"]
            else "offline"
            if seconds is None or seconds > get_settings().agent_offline_seconds
            else "online"
        )
        result.append(serialize_doc(agent))
    return result


@router.post("", status_code=201)
def provision_agent(body: AgentName, principal: Principal = Depends(require_admin)):
    return create_agent(principal, body.name)


@router.post("/{agent_id}/revoke")
def revoke_agent(agent_id: UUID, principal: Principal = Depends(require_admin)):
    changed = get_database().agents.update_one(
        scope(principal, {"agent_id": str(agent_id)}), {"$set": {"revoked": True}}
    )
    if not changed.matched_count:
        raise HTTPException(404, "Agent not found")
    audit(principal.org_id, principal.user_id, "agent.revoke", str(agent_id))
    return {"status": "revoked"}


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, agent=Depends(agent_identity)):
    get_database().agents.update_one(
        {"agent_id": agent["agent_id"], "revoked": False},
        {"$set": {"last_seen": datetime.now(UTC), "health": body.model_dump()}},
    )
    return {"status": "accepted"}


@router.post("/ingest")
async def ingest(body: ObservationBatch, agent=Depends(agent_identity)):
    if not _ingestion_slot.acquire(blocking=False):
        raise HTTPException(
            429, "Ingestion busy; retry the same batch", headers={"Retry-After": "5"}
        )
    try:
        # Recheck revocation immediately before processing, after dependency validation.
        if not await run_in_threadpool(
            lambda: get_database().agents.find_one(
                {"agent_id": agent["agent_id"], "revoked": False}
            )
        ):
            raise HTTPException(401, "Agent revoked")
        result = await run_in_threadpool(ingest_batch, agent, body)
        await get_connection_manager().broadcast(
            {"event": "ASSESSMENT_UPDATED", "org_id": agent["org_id"], **result}
        )
        return result
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Processing unavailable; retry the same batch") from None
    finally:
        _ingestion_slot.release()
