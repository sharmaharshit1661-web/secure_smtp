"""Durable integration outcomes, explicit failures, scoped graph relationships."""

import hashlib
import json
from datetime import UTC, datetime

from secure_smtp.alerts.engine import AlertEngine
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database


def sync_graph(org_id, job_id):
    settings, db = get_settings(), get_database()
    if not settings.neo4j_uri:
        return {"status": "disabled"}
    from neo4j import GraphDatabase

    sessions = list(
        db.sessions.find({"org_id": org_id, "job_id": job_id, "published": {"$ne": False}})
    )
    rows = [
        {
            "id": s["id"],
            "host_id": s["host_id"],
            "host": s["dst_ip"],
            "rules": [f["rule_id"] for f in s.get("findings", [])],
        }
        for s in sessions
    ]
    with GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        connection_timeout=5,
    ) as driver:
        # Composite uniqueness keeps retries/concurrent syncs from duplicating evidence.
        for label, field in [("MailHost", "id"), ("MailSession", "id"), ("Weakness", "rule_id")]:
            driver.execute_query(
                f"CREATE CONSTRAINT secure_smtp_{label.lower()} IF NOT EXISTS "
                f"FOR (n:{label}) REQUIRE (n.org_id, n.{field}) IS UNIQUE"
            )
        driver.execute_query(
            """UNWIND $rows AS row
            MERGE (h:MailHost {org_id:$org, id:row.host_id}) SET h.address=row.host
            MERGE (s:MailSession {org_id:$org, id:row.id}) SET s.job_id=$job
            MERGE (h)-[:OBSERVED]->(s)
            FOREACH (rule IN row.rules | MERGE (f:Weakness {org_id:$org, rule_id:rule}) MERGE (s)-[:EXHIBITS]->(f))""",
            rows=rows,
            org=org_id,
            job=job_id,
        )
    return {"status": "synced", "sessions": len(rows)}


def graph_shared_weaknesses(org_id):
    settings = get_settings()
    if not settings.neo4j_uri:
        return {"status": "disabled", "groups": []}
    from neo4j import GraphDatabase

    with GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
        connection_timeout=5,
    ) as driver:
        records, _, _ = driver.execute_query(
            """MATCH (h:MailHost {org_id:$org})-[:OBSERVED]->(s:MailSession {org_id:$org})-[:EXHIBITS]->(f:Weakness {org_id:$org})
            WITH f.rule_id AS rule, collect(DISTINCT h.address) AS hosts, collect(DISTINCT s.id)[..100] AS sessions
            WHERE size(hosts)>1 RETURN rule, hosts, sessions LIMIT 100""",
            org=org_id,
        )
        return {"status": "synced", "groups": [dict(record) for record in records]}


def deliver_alerts(org_id, job_id):
    db, engine = (
        get_database(),
        AlertEngine(
            min_severity=get_settings().alert_min_severity,
            risk_threshold=get_settings().alert_risk_threshold,
        ),
    )
    if not engine.enabled:
        return {"status": "disabled"}
    failed, sent, suppressed = 0, 0, 0
    for session in db.sessions.find(
        {"org_id": org_id, "job_id": job_id, "published": {"$ne": False}}
    ):
        score = (session.get("risk_score") or {}).get("score_0_100", 0)
        findings = session.get("findings", [])
        if not engine.should_alert(findings, score):
            continue
        # Suppress an identical weakness on the same host for an hour, across ingest retries.
        bucket = session.get("observed_at", session.get("created_at", datetime.now(UTC))).strftime(
            "%Y-%m-%dT%H"
        )
        key = hashlib.sha256(
            json.dumps(
                [org_id, session["dst_ip"], sorted(f["rule_id"] for f in findings), bucket]
            ).encode()
        ).hexdigest()
        delivery = db.alert_deliveries.find_one({"dedupe_key": key})
        if delivery and delivery["status"] == "sent":
            suppressed += 1
            continue
        db.alert_deliveries.update_one(
            {"dedupe_key": key},
            {
                "$set": {
                    "org_id": org_id,
                    "job_id": job_id,
                    "session_id": session["id"],
                    "status": "pending",
                    "updated_at": datetime.now(UTC),
                },
                "$inc": {"attempts": 1},
            },
            upsert=True,
        )
        success = engine.send(
            session["id"],
            session["src_ip"],
            session["dst_ip"],
            session["protocol"],
            score,
            findings,
            session.get("source_kind", ""),
            delivery_id=key,
        )
        db.alert_deliveries.update_one(
            {"dedupe_key": key},
            {"$set": {"status": "sent" if success else "failed", "updated_at": datetime.now(UTC)}},
        )
        sent += int(success)
        failed += int(not success)
    return {
        "status": "failed" if failed else "delivered",
        "sent": sent,
        "failed": failed,
        "suppressed": suppressed,
    }


def run_integrations(org_id, job_id):
    result = {}
    for name, function in [("graph", sync_graph), ("alerts", deliver_alerts)]:
        try:
            result[name] = function(org_id, job_id)
        except Exception:
            result[name] = {
                "status": "failed",
                "error": "Integration unavailable; retry after checking configuration.",
            }
    get_database().analysis_jobs.update_one(
        {"org_id": org_id, "job_id": job_id}, {"$set": {"integrations": result}}
    )
    return result
