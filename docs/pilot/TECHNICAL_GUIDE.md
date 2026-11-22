# Secure SMTP: technical guide

Public Clerk registration is now supported. See [public registration and login](PUBLIC_REGISTRATION.md); it supersedes the invitation-only descriptions below for personal accounts.

## Purpose and boundaries
Secure SMTP observes email transport security for SMTP, IMAP and POP3. It produces session evidence, rule findings, risk summaries and assessment reports. It is a passive posture tool, not a mail gateway, antivirus engine or proven attack-prevention system. Suspected downgrade behavior is not proof of an attacker. Passive observations cannot establish certificate trust or compliance certification.

## Stack
React 19 and Vite provide the browser application; React Router handles navigation and Recharts renders charts. FastAPI/Pydantic provide the API and input validation. MongoDB stores operational records. Scapy parses captures, cryptography reads certificate metadata, and rules calculate findings. Python risk/anomaly modules supplement rules; batch anomaly output is not a validated historical baseline. ReportLab/WeasyPrint create PDFs and Jinja produces escaped HTML. Neo4j projects relationships for shared-weakness investigations. Caddy terminates HTTPS; nginx serves the frontend. Docker Compose describes a single-instance pilot.

## User login
Online/private connected installations use Clerk. Configure the real frontend publishable key, backend HTTPS issuer, allowed application origin and pilot organization ID. Invite users into that organization and assign administrator/member roles. A browser sign-in obtains a short-lived session token; the client supplies it as an Authorization Bearer header. The backend verifies RS256 signature using issuer JWKS, time/session claims, authorized party, organization and any configured audience. It independently enforces admin permissions. The browser's identity check must succeed before opening the dashboard. Missing configuration never grants demo access. No shared browser API key or unsigned local token is accepted.

Users without pilot membership cannot access records. Administrators provision/revoke agents and delete assessments; analysts investigate and export scoped reports. Provider-side revocation/role changes become effective when existing short-lived tokens expire; immediate revocation introspection is not implemented. MFA and invitation policy must be configured in the actual Clerk application. A publishable key alone does not configure the backend or prove the login flow works.

Fully disconnected installations instead use local Keycloak with PKCE, client roles and backend issuer/audience/signature checks. They require local DNS, trusted HTTPS, time synchronization and persistent identity storage. Clerk requires network access to its services.

## Data flow
1. An authorized collector captures both directions at a mail server or mirrored source. Bounded flow buffers extract transport metadata. Email bodies and credentials are excluded from agent telemetry.
2. A durable, bounded SQLite outbox queues batches. Stable batch/event IDs allow retry after network failure; heartbeats report capture status and drops.
3. HTTPS ingestion authenticates the unique agent credential against its stored hash, checks revocation and organization, and validates a closed schema. Credentials for users and agents are distinct.
4. Ingestion creates an assessment/job, deduplicates events, creates hosts/sessions, evaluates rules and risk, and generates job-scoped reports. Staged records become visible after successful completion. Completed retries repair interrupted publication.
5. Integration results persist separately. Neo4j receives relationships; configured webhooks receive qualifying alerts. Failures remain visible and retryable.
6. Authenticated, organization-scoped WebSocket notifications and periodic API polling refresh the browser. The browser reconnects with a fresh token; missing updates must not imply fresh data.

Manual PCAP upload follows capture framing/size validation, single-job admission and a bounded subprocess. The default ceiling is 25 MiB, 100,000 packets, 2,000 streams and 120 seconds. Upload bytes are temporary. Reports use records belonging to the requested completed job, not the whole database.

## Storage and API boundaries
MongoDB stores agents, hosts, sessions, analysis jobs, alert outcomes, audit events, remediation tracking and replay tombstones. Queries include verified organization scope; unpublished staging records are excluded from investigation reads. Report identifiers are validated and downloads require an owned completed job. Fresh Compose volumes create a readWrite application user limited to secure_smtp_pilot; backend containers do not receive root credentials. Existing volumes require a deliberate backed-up migration.

API groups cover identity, hosts, sessions, compliance, analysis, reports, agents, operations, graph and remediation. Administrative actions are backend protected. All /api/ request bodies are bounded, with a separate upload ceiling. Size limits do not replace rate limits. Health checks check database availability and identity configuration, not the actual provider login journey.

## Neo4j integration
MongoDB is the operational source of truth; Neo4j is a derived investigation graph. MailHost nodes OBSERVED MailSession nodes, which EXHIBITS Weakness nodes. Every node includes org_id. Host/session keys and weakness rule IDs have composite uniqueness constraints with organization scope. Parameterized queries synchronize completed published evidence and locate hosts sharing weaknesses, linking results to supporting session IDs. Session evidence lists are bounded to 100 IDs per group.

Use docker-compose.graph.yml together with the selected base Compose file and supply GRAPH_PASSWORD privately. Graph data persists in graph_data and ports are not published. Connection failures surface as failed integration status or HTTP 503, rather than empty success. Administrator retry is available for completed assessments. Deletion removes corresponding graph evidence before declaring assessment deletion complete. Concurrent integration/deletion operations and real-server outage recovery still need deployment verification. The initial graph credential needs schema-creation permissions for constraints; establish an appropriate service-account policy for the chosen Neo4j edition. Live server execution has not been verified in this workspace.

## UI workflows
Fleet overview summarizes observed hosts and risk. Session Explorer provides evidence, findings and remediation tracking. Ingest accepts captures and exposes job state/reports. Monitoring & operations provisions agents, lists assessments and presents graph/alert/retention results. The AI page distinguishes templates from externally generated responses. Controlled lab tools are administrator-only and disabled in pilot deployment. Light/dark theme preferences are local browser settings. Empty graph/remediation states explain the next action; failed access checks never fabricate an administrator identity.

## Operational safeguards
Agent credentials are shown once and stored hashed. Revoke and reprovision if lost. Logs must exclude credentials and message content. Keep secrets outside frontend VITE variables. Review optional external AI/webhook data handling before enabling them. Reports escape untrusted text and the PDF resource fetcher rejects external resources. Unknown TLS fields stay unknown; lab fingerprints are not fabricated. Remediation disappearance from samples never proves resolution.

Retention defaults to 30 days for metadata/reports, with replay tombstones preventing deleted agent evidence from being recreated immediately. Backup MongoDB and report volumes consistently; offline deployments must also back up Keycloak/PostgreSQL and Caddy CA state. Test restores into separate storage. One backend worker/instance is required: admission locks and the socket broker are process-local. Durable distributed queues, horizontal scaling, load limits and HA are unfinished expansion work.

## Running and verifying
See README.md and NETWORK.md in this directory for configuration and installation. Use the project interpreter with `python -m pytest`; the copied virtual environment can contain stale executable shebangs. Frontend commands are npm --workspace frontend test, run lint and run build. scripts/rehearse_pilot.py uses disposable MongoDB and a signed local webhook to exercise ingestion, scoped reports, restart and restoration. scripts/rehearse_database_permissions.py tests the application database account. Test scripts never substitute for the real identity/browser/collector journey.

## Release limits and review questions
Before pilot approval, verify real Clerk or Keycloak login, admin/analyst/unauthorized accounts, HTTPS and private ports, authorized SMTP/IMAP/POP3 capture, offline replay, revocation, browser controls, Neo4j outage recovery, notifications and restored reports. Scan target container images and configure ingress abuse limits. Docker and local browser verification were unavailable in this chat. No independent penetration test, government/defence certification, SLA or commercial readiness is claimed.

Be prepared to explain: why passive TLS visibility is limited; how tenant scope is enforced; what constitutes evidence versus suspicion; why duplicate events are safe; what happens on process restart; where plaintext lives; how secrets are rotated; why a failed graph does not erase MongoDB evidence; why anomaly outputs require evaluation; what the collector misses on an incorrect mirror; how a backup is proven recoverable; and which failure modes remain outside the single-instance pilot.
