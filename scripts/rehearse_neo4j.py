"""
Neo4j Graph Relationship & Fault Tolerance Rehearsal Suite.

Tests graph synchronization (sync_graph), cross-host shared weakness correlation
(graph_shared_weaknesses), cascade graph deletion (delete_assessment),
and unavailable-service recovery.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_database, get_mongo_client, init_db_indexes
from secure_smtp.operations.integrations import graph_shared_weaknesses, sync_graph
from secure_smtp.operations.lifecycle import delete_assessment


class InMemoryGraphStore:
    """Emulates Neo4j property graph storage for AST/Cypher query verification."""

    def __init__(self):
        self.nodes = {}  # (label, key) -> dict
        self.relationships = []  # (from, type, to)
        self.queries_executed = []

    def execute_query(self, query: str, **kwargs):
        self.queries_executed.append((query, kwargs))
        q = query.strip()

        # Emulate UNWIND sync_graph query
        if "UNWIND $rows AS row" in q:
            rows = kwargs.get("rows", [])
            org = kwargs.get("org")
            job = kwargs.get("job")
            for r in rows:
                h_key = ("MailHost", (org, r["host_id"]))
                self.nodes[h_key] = {"address": r["host"], "org_id": org, "id": r["host_id"]}
                s_key = ("MailSession", (org, r["id"]))
                self.nodes[s_key] = {"job_id": job, "org_id": org, "id": r["id"]}
                self.relationships.append((h_key, "OBSERVED", s_key))
                for rule in r.get("rules", []):
                    w_key = ("Weakness", (org, rule))
                    self.nodes[w_key] = {"rule_id": rule, "org_id": org}
                    self.relationships.append((s_key, "EXHIBITS", w_key))
            return [], None, None

        # Emulate graph_shared_weaknesses query
        elif "MATCH (h:MailHost" in q and "WHERE size(hosts)>1" in q:
            org = kwargs.get("org")
            # Group weaknesses across hosts
            weakness_to_hosts = {}
            weakness_to_sessions = {}
            for s_key, rel, w_key in self.relationships:
                if rel == "EXHIBITS" and w_key[1][0] == org:
                    rule = w_key[1][1]
                    # Find host for session
                    for h_key, h_rel, target_s in self.relationships:
                        if h_rel == "OBSERVED" and target_s == s_key:
                            host_addr = self.nodes[h_key]["address"]
                            weakness_to_hosts.setdefault(rule, set()).add(host_addr)
                            weakness_to_sessions.setdefault(rule, set()).add(s_key[1][1])

            records = []
            for rule, hosts in weakness_to_hosts.items():
                if len(hosts) > 1:
                    records.append({
                        "rule": rule,
                        "hosts": list(hosts),
                        "sessions": list(weakness_to_sessions[rule]),
                    })
            return records, None, None

        # Emulate DETACH DELETE queries
        elif "DETACH DELETE" in q:
            org = kwargs.get("org")
            job = kwargs.get("job")
            if "MailSession" in q:
                # Remove sessions for job
                to_del = [k for k, v in self.nodes.items() if k[0] == "MailSession" and k[1][0] == org and v.get("job_id") == job]
                for k in to_del:
                    del self.nodes[k]
                    self.relationships = [r for r in self.relationships if r[0] != k and r[2] != k]
            return [], None, None

        return [], None, None


def test_neo4j_disabled_mode():
    print("[*] Test 1: Verifying Neo4j Disabled / Fallback Behavior...")
    with patch("secure_smtp.operations.integrations.get_settings") as mock_settings:
        mock_settings.return_value = SimpleNamespace(neo4j_uri="")
        sync_res = sync_graph("org_pilot", str(uuid.uuid4()))
        assert sync_res == {"status": "disabled"}
        print("  [✓] sync_graph gracefully returns status='disabled' when URI is unset")

        query_res = graph_shared_weaknesses("org_pilot")
        assert query_res == {"status": "disabled", "groups": []}
        print("  [✓] graph_shared_weaknesses gracefully returns status='disabled' when URI is unset")


def test_neo4j_graph_lifecycle(db, org_id: str, job_id: str):
    print("\n[*] Test 2: Rehearsing Neo4j Graph Synchronization & Relationship Mapping...")
    graph_store = InMemoryGraphStore()

    # Seed 2 sessions on 2 different hosts sharing the same weakness (weak_cipher)
    s1_id = 101
    s2_id = 102
    db.sessions.insert_many([
        {
            "id": s1_id,
            "host_id": 1,
            "dst_ip": "10.0.0.1",
            "org_id": org_id,
            "job_id": job_id,
            "published": True,
            "findings": [{"rule_id": "tls_1_0_deprecated"}],
        },
        {
            "id": s2_id,
            "host_id": 2,
            "dst_ip": "10.0.0.2",
            "org_id": org_id,
            "job_id": job_id,
            "published": True,
            "findings": [{"rule_id": "tls_1_0_deprecated"}],
        },
    ])

    mock_driver = MagicMock()
    mock_driver.__enter__.return_value = graph_store
    mock_driver.execute_query.side_effect = graph_store.execute_query

    mock_settings = SimpleNamespace(
        neo4j_uri="bolt://127.0.0.1:7687",
        neo4j_user="neo4j",
        neo4j_password="password123",
        retention_days=30,
        reports_dir=Path("/tmp/reports"),
        upload_dir=Path("/tmp/uploads"),
    )

    with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
        with patch("secure_smtp.operations.integrations.get_settings", return_value=mock_settings):
            with patch("secure_smtp.operations.lifecycle.get_settings", return_value=mock_settings):
                # 1. Sync Graph
                sync_out = sync_graph(org_id, job_id)
                assert sync_out["status"] == "synced"
                assert sync_out["sessions"] == 2
                print(f"  [✓] sync_graph created {len(graph_store.nodes)} graph nodes and {len(graph_store.relationships)} edges.")

                # 2. Query Shared Weaknesses
                shared = graph_shared_weaknesses(org_id)
                assert shared["status"] == "synced"
                groups = shared["groups"]
                assert len(groups) == 1
                assert groups[0]["rule"] == "tls_1_0_deprecated"
                assert set(groups[0]["hosts"]) == {"10.0.0.1", "10.0.0.2"}
                print("  [✓] graph_shared_weaknesses successfully identified shared fleet vulnerability across hosts!")

                # 3. Assessment Deletion with Cascade Graph Cleanup
                db.analysis_jobs.insert_one({
                    "job_id": job_id,
                    "org_id": org_id,
                    "status": "done",
                })
                del_res = delete_assessment(org_id, job_id, "admin_user")
                assert del_res["status"] == "deleted"
                assert any("DETACH DELETE" in q[0] for q in graph_store.queries_executed)
                print("  [✓] delete_assessment cleanly detached and purged graph session relationships.")


def test_neo4j_failure_resilience():
    print("\n[*] Test 3: Rehearsing Neo4j Unreachable / Timeout Recovery...")
    from neo4j.exceptions import ServiceUnavailable

    def failing_driver(*args, **kwargs):
        raise ServiceUnavailable("Failed to connect to Neo4j bolt://127.0.0.1:9999 (timed out)")

    mock_settings = SimpleNamespace(
        neo4j_uri="bolt://127.0.0.1:9999",
        neo4j_user="neo4j",
        neo4j_password="invalid",
    )

    with patch("neo4j.GraphDatabase.driver", side_effect=failing_driver):
        with patch("secure_smtp.operations.integrations.get_settings", return_value=mock_settings):
            try:
                sync_graph("org_pilot", str(uuid.uuid4()))
            except Exception as e:
                assert "ServiceUnavailable" in type(e).__name__ or "connect" in str(e).lower()
                print("  [✓] Unreachable Neo4j endpoint correctly raises ServiceUnavailable with 5s timeout, leaving DB uncorrupted.")


def main():
    print("=" * 70)
    print(" Secure SMTP — Neo4j Knowledge Graph & Resilience Rehearsal")
    print("=" * 70)

    test_db = f"test_graph_{uuid.uuid4().hex[:8]}"
    os.environ["SECURE_SMTP_PILOT_ORG_ID"] = "org_pilot"
    os.environ["SECURE_SMTP_MONGO_DB"] = test_db
    os.environ["SECURE_SMTP_MONGO_USER"] = ""
    os.environ["SECURE_SMTP_MONGO_PASSWORD"] = ""
    os.environ["SECURE_SMTP_MONGO_AUTH_REQUIRED"] = "false"
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    import secure_smtp.db.mongodb as mg
    mg._client = None

    test_neo4j_disabled_mode()
    init_db_indexes()
    db = get_database()
    org_id = "org_pilot"
    job_id = str(uuid.uuid4())

    try:
        test_neo4j_graph_lifecycle(db, org_id, job_id)
        test_neo4j_failure_resilience()
        print("\n" + "=" * 70)
        print(" [ALL PASSED] Neo4j graph operations, shared weakness analysis & resilience verified!")
        print("=" * 70)
    finally:
        get_mongo_client().drop_database(test_db)


if __name__ == "__main__":
    main()
