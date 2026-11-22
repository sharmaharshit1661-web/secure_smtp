"""Persistent, idempotent agent ingestion and assessment ownership."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

from fastapi import HTTPException
from pymongo.errors import DuplicateKeyError

from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database, get_next_sequence
from secure_smtp.monitoring.analysis import score_observation


def now():
    return datetime.now(UTC)


def audit(org_id, actor, action, target, outcome="success"):
    get_database()["audit"].insert_one(
        {
            "org_id": org_id,
            "actor": actor,
            "action": action,
            "target": target,
            "outcome": outcome,
            "created_at": now(),
        }
    )


def create_agent(principal, name):
    agent_id, secret = str(uuid4()), secrets.token_urlsafe(32)
    get_database()["agents"].insert_one(
        {
            "agent_id": agent_id,
            "org_id": principal.org_id,
            "name": name,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "revoked": False,
            "created_at": now(),
            "created_by": principal.user_id,
            "last_seen": None,
        }
    )
    audit(principal.org_id, principal.user_id, "agent.create", agent_id)
    return {"agent_id": agent_id, "credential": f"sa_{agent_id}.{secret}"}


def authenticate_agent(token):
    try:
        identity, secret = token.split(".", 1)
        agent_id = identity.removeprefix("sa_")
        if not identity.startswith("sa_") or len(secret) > 128:
            raise ValueError()
    except (AttributeError, ValueError):
        raise HTTPException(401, "Invalid agent credential") from None
    agent = get_database()["agents"].find_one({"agent_id": agent_id, "revoked": False})
    if not agent or not secrets.compare_digest(
        agent["secret_hash"], hashlib.sha256(secret.encode()).hexdigest()
    ):
        raise HTTPException(401, "Invalid or revoked agent credential")
    if agent["org_id"] != get_settings().pilot_org_id:
        raise HTTPException(403, "Agent organization is not enabled")
    return agent


def event_digest(observation):
    return hashlib.sha256(observation.model_dump_json().encode()).hexdigest()


def refresh_hosts(org_id):
    db = get_database()
    from secure_smtp.ai.risk_model import compute_host_rollup
    from secure_smtp.db.models import RiskScore

    for host in db.hosts.find({"org_id": org_id}):
        records = list(
            db.sessions.find({"org_id": org_id, "host_id": host["id"], "published": {"$ne": False}})
        )
        if not records and db.sessions.find_one(
            {"org_id": org_id, "host_id": host["id"], "published": False}
        ):
            db.hosts.update_one(
                {"org_id": org_id, "id": host["id"]}, {"$set": {"published": False}}
            )
            continue
        if not records:
            db.hosts.delete_one({"org_id": org_id, "id": host["id"]})
            continue
        scores = [RiskScore(**s["risk_score"]) for s in records if s.get("risk_score")]
        db.hosts.update_one(
            {"org_id": org_id, "id": host["id"]},
            {
                "$set": {
                    "published": True,
                    "session_count": len(records),
                    "aggregate_risk_score": compute_host_rollup(scores) if scores else None,
                }
            },
        )


def ingest_batch(agent, batch):
    db, org_id, agent_id = get_database(), agent["org_id"], agent["agent_id"]
    job_id = str(uuid5(NAMESPACE_URL, agent_id + ":" + str(batch.batch_id)))
    payload_hash = hashlib.sha256(batch.model_dump_json().encode()).hexdigest()
    key = {"org_id": org_id, "job_id": job_id}
    # Unique job IDs and event indexes survive worker/process restarts.
    try:
        db.analysis_jobs.update_one(
            key,
            {
                "$setOnInsert": {
                    **key,
                    "owner_id": agent_id,
                    "agent_id": agent_id,
                    "source_kind": "passive_agent",
                    "payload_hash": payload_hash,
                    "status": "queued",
                    "created_at": now(),
                }
            },
            upsert=True,
        )
    except DuplicateKeyError:
        pass
    job = db.analysis_jobs.find_one(key)
    if job["payload_hash"] != payload_hash:
        raise HTTPException(409, "Batch ID was already used with different observations")
    if job["status"] in ("deleted", "deleting"):
        raise HTTPException(410, "Assessment was deleted; replay is not accepted")
    if job["status"] == "done":
        # A crash after report completion may precede publication or host refresh.
        db.sessions.update_many(key, {"$set": {"published": True}})
        refresh_hosts(org_id)
        return {"job_id": job_id, "status": "done", "duplicate": True}
    run_id = str(uuid4())
    lease = {**key, "status": "running", "run_id": run_id}
    claimed = db.analysis_jobs.update_one(
        {**key, "status": {"$in": ["queued", "failed"]}},
        {"$set": {"status": "running", "run_id": run_id, "error_message": None}},
    )
    if not claimed.modified_count:
        raise HTTPException(409, "Assessment is already processing or deleting")
    try:
        for observation in batch.observations:
            if observation.observed_at < now() - timedelta(days=get_settings().retention_days):
                raise HTTPException(422, "Observation is outside the retention window")
            event_key = {
                "org_id": org_id,
                "agent_id": agent_id,
                "event_id": str(observation.event_id),
            }
            existing = db.sessions.find_one(event_key)
            if existing:
                if existing["event_hash"] != event_digest(observation):
                    raise HTTPException(409, "Event ID reused with different data")
                continue
            # Tombstones prevent delayed retries from recreating intentionally deleted evidence.
            if db.event_tombstones.find_one(event_key):
                continue
            host_key = {"org_id": org_id, "ip_or_hostname": str(observation.dst_ip)}
            db.hosts.update_one(
                host_key,
                {
                    "$setOnInsert": {
                        **host_key,
                        "id": get_next_sequence("host_id"),
                        "published": False,
                        "session_count": 0,
                        "aggregate_risk_score": None,
                    }
                },
                upsert=True,
            )
            host = db.hosts.find_one(host_key)
            document = score_observation(observation, get_next_sequence("session_id"), host["id"])
            document.update(
                published=False,
                **event_key,
                event_hash=event_digest(observation),
                job_id=job_id,
                owner_id=agent_id,
                source_kind="passive_agent",
                observed_at=observation.observed_at,
                created_at=now(),
                capture_complete=observation.capture_complete,
            )
            db.sessions.update_one(event_key, {"$setOnInsert": document}, upsert=True)
        from secure_smtp.api.pipeline import generate_job_reports

        generate_job_reports(job_id)
        completed = db.analysis_jobs.update_one(
            lease, {"$set": {"status": "done", "completed_at": now()}}
        )
        if not completed.modified_count:
            raise RuntimeError("Assessment lease expired")
        db.sessions.update_many(key, {"$set": {"published": True}})
        refresh_hosts(org_id)
        db.agents.update_one(
            {"agent_id": agent_id, "revoked": False},
            {"$set": {"last_ingest": now(), "last_error": None}},
        )
        from secure_smtp.operations.integrations import run_integrations

        run_integrations(org_id, job_id)
        return {"job_id": job_id, "status": "done", "duplicate": False}
    except Exception:
        db.analysis_jobs.update_one(
            lease,
            {
                "$set": {
                    "status": "failed",
                    "error_message": "Metadata processing failed; the agent will retry.",
                }
            },
        )
        db.agents.update_one({"agent_id": agent_id}, {"$set": {"last_error": "ingestion_failed"}})
        raise
