# Pilot and finale checklist

Legend: **Implemented locally** means code/tests, not deployed acceptance. Remaining gates require configured external services, authorized traffic or organizational review.

| # | Priority | Commitment | Current evidence / remaining gate |
|---|---|---|---|
| 1 | P0 | Verified authentication | Implemented & rehearsed: Clerk & Keycloak RS256 token verification, claims validation, and RBAC verified in `scripts/rehearse_identity_provider.py`. Live provider probing via `scripts/validate_identity_provider.py`. |
| 2 | P0 | Remove hardcoded credentials | Browser/backend fallback removed; Compose and Mongo setup require supplied secrets. Repository audited clean (zero leaks); rotation tool & checklist provided in `scripts/rotate_credentials.py`. |
| 3 | P0 | Pilot ownership and admin checks | Implemented locally for API reads/reports and lab controls. Fresh pilot DB required; no legacy migration performed. |
| 4 | P0 | Continuous monitoring agent | Implemented & rehearsed: authorized passive collector, stream parsing, and metadata-only observation. Multi-profile SMTP traffic generation & forensic evaluation verified in `scripts/rehearse_authorized_traffic.py`. |
| 5 | P0 | Authenticated agent ingestion | Implemented locally: strict schema, one-time unique credentials stored as hashes, admin provisioning/revocation, HTTPS ingestion. Real agent connectivity rehearsal remains. |
| 6 | P0 | Agent interruptions | Implemented locally: heartbeat, online/offline, bounded SQLite WAL buffer, retry, event/batch deduplication and tombstones. Restart rehearsal remains. |
| 7 | P0 | Live dashboard analysis | Implemented locally: authenticated org socket receives agent event, views poll every 15 seconds and show stale failures; the durable queue recovers missed updates. Rehearsal remains. |
| 8 | P0 | Accurate findings | Implemented locally: missing certificate and handshake values remain unknown, partial captures cannot assert stripped STARTTLS, rule labels distinguish observation from attack. Real traffic validation remains. |
| 9 | P0 | AI/simulation labels | Implemented locally: template/external source labels, no invented fleet weights/PQC score, stored lab/replay/agent provenance. |
| 10 | P0 | Assessment/report scope | Implemented locally with owned jobs, sessions and job-specific report rollups. Deployed report rehearsal pending. |
| 11 | P0 | Upload hardening | Implemented locally: byte/framing/packet/stream/reassembly/concurrency/time limits. Deployment capacity and hostile-PCAP fuzzing pending. |
| 12 | P0 | Full HTTPS deployment | Compose/Caddy prepared; multi-stage Dockerfiles, Compose YAML, Caddy route matching, network isolation, and Keycloak realm validated in `scripts/rehearse_docker_deployment.py`. |
| 13 | P0 | Persistence and recovery | Volumes, health/restart configuration and interrupted-job state implemented. Local mongodump/mongorestore rehearsal passed against a separate database with report byte comparison. Repeat on deployed storage. |
| 14 | P0 | Deployed journey | Code paths are ready. Deployment, verified identity, real collector host, backup restore and deployed journey are acceptance gates before pilot use. |
| 15 | P1 | Neo4j relationships | Implemented & rehearsed: org-scoped host/session/finding evidence, shared-weakness Cypher queries, cascade deletion, and 5s timeout resilience verified in `scripts/rehearse_neo4j.py`. |
| 16 | P1 | Alert delivery | Implemented locally: configurable threshold, persistent attempts/status, hourly dedupe key and receiver delivery ID. A signed local HTTP receiver accepted a real generated alert. Verify the external receiver on deployment. |
| 17 | P1 | Onboarding | Implemented locally: installation, where-to-run, permission, heartbeat and troubleshooting instructions. Pilot invite remains. |
| 18 | P1 | Administrator/analyst roles | Implemented locally: admin-only provisioning/revoke/delete/retry controls and analyst read/investigation access. Signed-in role rehearsal remains. |
| 19 | P1 | Retention/deletion/privacy | Implemented locally: configurable metadata/report retention, assessment deletion, tombstones, audit events and payload-free monitoring. Recovery rehearsal remains. |
| 20 | P1 | Remediation workflow | Implemented locally: finding-linked tracking and later same-source observations; missing from a sample never marks resolved. |
| 21 | P1 | Operational visibility | Implemented locally: durable admin audit, ingestion failures, alert delivery outcomes, retention health and integration status. |
| 22 | P1 | Release materials | Setup, limitations, checklist and rehearsal procedure added. Real traffic demonstration and recovery rehearsal pending. |
| 23 | P2 | Multi-organization onboarding | Pending; deployment intentionally permits a single pilot org. |
| 24 | P2 | Durable queues/scaling | Pending; one worker/instance only. |
| 25 | P2 | Load/capacity testing | Implemented & verified: ~1,000 req/s health checks, ~770 req/s session queries, 144 events/s ingestion throughput, and 512 KiB flood defense verified in `scripts/rehearse_load_testing.py`. |
| 26 | P2 | Independent security/dependency review | Local adversarial review and current Python/npm scans recorded in SECURITY_AUDIT.md. Independent review and container/OS scanning remain pending. |
| 27 | P2 | Managed agent lifecycle | Pending. |
| 28 | P2 | Authorized active TLS checks | Pending. |
| 29 | P2 | Historical anomaly baselines | Pending; batch anomaly output is not a longitudinal validated model. |
| 30 | P2 | Evidence-based remediation resolution | Pending. |
| 31 | P2 | Incident integrations | Pending. |
| 32 | P2 | HA/DR/support commitments | Pending; no SLA, RPO or RTO claimed. |
| 33 | P2 | Privacy/customer arrangements | Pending organizational review; no compliance certification claimed. |

Release gate: do not call the full P0 pilot ready while any P0 gate above remains open.
