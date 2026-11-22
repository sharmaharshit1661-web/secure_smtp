"""Idempotent deletion and retention. Tombstones stop delayed agent resurrection."""

import shutil
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import HTTPException

from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database
from secure_smtp.monitoring.service import audit, refresh_hosts


def delete_assessment(org_id, job_id, actor):
    db = get_database()
    job_id = str(UUID(job_id))
    key = {"org_id": org_id, "job_id": job_id}
    job = db.analysis_jobs.find_one(key)
    if not job:
        raise HTTPException(404, "Assessment not found")
    if job["status"] in ("queued", "running"):
        raise HTTPException(409, "Wait for processing to finish before deletion")
    claimed = db.analysis_jobs.update_one(
        {**key, "status": {"$in": ["done", "failed", "deleting", "deleted"]}},
        {"$set": {"status": "deleting"}},
    )
    if not claimed.matched_count:
        raise HTTPException(409, "Assessment state changed; refresh before deletion")
    # Delete graph first. On failure leave deletion visible/retryable, never claim success.
    settings = get_settings()
    if settings.neo4j_uri:
        from neo4j import GraphDatabase

        with GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
            connection_timeout=5,
        ) as driver:
            driver.execute_query(
                "MATCH (s:MailSession {org_id:$org, job_id:$job}) DETACH DELETE s",
                org=org_id,
                job=job_id,
            )
            driver.execute_query(
                "MATCH (f:Weakness {org_id:$org}) WHERE NOT ()-[:EXHIBITS]->(f) DETACH DELETE f",
                org=org_id,
            )
            driver.execute_query(
                "MATCH (h:MailHost {org_id:$org}) WHERE NOT (h)-[:OBSERVED]->() DETACH DELETE h",
                org=org_id,
            )
    for record in db.sessions.find(key):
        if record.get("event_id"):
            event_key = {k: record[k] for k in ("org_id", "agent_id", "event_id")}
            db.event_tombstones.update_one(
                event_key,
                {
                    "$set": {
                        "expires_at": datetime.now(UTC)
                        + timedelta(days=settings.retention_days + 1)
                    }
                },
                upsert=True,
            )
    db.sessions.delete_many(key)
    db.alert_deliveries.delete_many(key)
    db.remediations.delete_many(key)
    shutil.rmtree(settings.reports_dir / job_id, ignore_errors=False) if (
        settings.reports_dir / job_id
    ).exists() else None
    for path in settings.upload_dir.glob(job_id + ".*"):
        path.unlink(missing_ok=True)
    db.analysis_jobs.update_one(
        key,
        {
            "$set": {"status": "deleted", "deleted_at": datetime.now(UTC)},
            "$unset": {"pcap_filename": "", "integrations": ""},
        },
    )
    refresh_hosts(org_id)
    audit(org_id, actor, "assessment.delete", job_id)
    return {"status": "deleted"}


def enforce_retention(org_id):
    settings, db = get_settings(), get_database()
    cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days)
    deleted = 0
    for job in db.analysis_jobs.find(
        {
            "org_id": org_id,
            "created_at": {"$lt": cutoff},
            "status": {"$in": ["done", "failed", "deleting"]},
        }
    ):
        delete_assessment(org_id, job["job_id"], "retention_service")
        deleted += 1
    db.audit.delete_many({"org_id": org_id, "created_at": {"$lt": cutoff}})
    # Deleted batch identifiers remain as compact replay tombstones until after the retention window.
    db.analysis_jobs.delete_many(
        {"org_id": org_id, "status": "deleted", "deleted_at": {"$lt": cutoff}}
    )
    return deleted
