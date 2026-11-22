# Secure SMTP pilot readiness

Local automated checks and isolated recovery rehearsals passed on 2026-11-22. This is not deployment approval. See [the current security audit](SECURITY_AUDIT.md) for evidence and open release gates.

## How people sign in

1. The administrator configures verified sign-in and enables Email and Organizations in the pilot Clerk instance. Invite each person to the configured organization using their own email. Assign an administrator or member role.
2. The person opens the invitation, accepts it and completes Clerk’s sign-in or account creation with the invited email. The verification method follows the settings in that Clerk instance. Returning members can open the pilot website and choose **Sign in**.
3. Select the pilot organization if prompted. Secure SMTP checks the signed session through the backend before opening the dashboard. A personal account or a different organization sees the organization selector. A failed service check has a retry action.
4. Members can investigate sessions and download their organization’s reports. Administrators can also create and revoke collectors and delete assessments. A collector receives its own one-time credential from Monitoring & operations.

[Clerk organization invitations](https://clerk.com/docs/guides/organizations/add-members/invitations)

## Implemented foundation

- Browser calls use current Clerk Bearer session tokens. Local demo login no longer unlocks the console. Missing Clerk configuration shows a configuration notice.
- Backend verifies RS256 signatures against the configured issuer's JWKS, issuer, time claims, required session claims, authorized party, and active pilot organization. Optional audience validation is enabled when configured. Clerk v1 and v2 organization claims are supported. Role `admin` is required for administrative controls. Anonymous mode and old API-key headers/query parameters cannot bypass this boundary.
- Hosts, sessions, compliance, AI context, jobs and reports use verified organization filters. Records without organization ownership are inaccessible. Report access requires an owned completed job and UUID identifier. Reports recompute host counts/scores from that job's sessions.
- WebSockets check Origin, require authentication within five seconds before broker registration, and disconnect at token expiry. Broadcasts require matching organization ownership. The browser obtains a fresh token on reconnect.
- Uploads default to 25 MiB, 100,000 packets, 2,000 streams and one assessment at a time. Capture framing is validated, TCP reassembly is capped at 8 MiB per direction, and a separate analysis process has a 120-second deadline. Captures are removed after processing. On API restart, queued/running jobs are marked failed for explicit re-upload.
- HTML reports escape untrusted fields; the PDF renderer cannot fetch external resources. Report downloads use authenticated fetch, with no credentials in URLs.
- Unvalidated certificate chains are unknown. AI templates identify their source, never mark remediation resolved, and no longer invent fleet SHAP weights or post-quantum readiness. Failed STARTTLS is not described as proof of an attack.
- Compose prepares a single-instance HTTPS stack with Caddy, private backend/database ports, persistent MongoDB/report volumes, restart policies and health checks. The mail lab and outbound alerts are disabled in the pilot Compose file.

## Configuration before starting

1. Supply the hosting provider, public domain and Clerk pilot organization ID. Point DNS at the host and allow inbound 80/443. Docker is not installed in the current execution environment; this Compose stack has not been run here.
2. Create a Clerk application and organization. Require verified sign-in, invite the approved pilot members, and assign organization administrator/member roles. Disable unwanted public enrollment in Clerk. Organization membership is enforced on the backend even if somebody creates an unrelated account.
3. Copy `.env.example` to a private deployment environment file. Set `PILOT_DOMAIN`, the public `VITE_CLERK_PUBLISHABLE_KEY`, `SECURE_SMTP_CLERK_ISSUER`, `SECURE_SMTP_PILOT_ORG_ID`, and separate new MongoDB administrator (`MONGO_ROOT_USER` / `MONGO_ROOT_PASSWORD`) and application (`SECURE_SMTP_MONGO_USER` / `SECURE_SMTP_MONGO_PASSWORD`) credentials. Never place a backend secret in a `VITE_` variable. No shared API key is needed.
4. Configure the Clerk application origin to the exact HTTPS site origin. `SECURE_SMTP_CLERK_AUTHORIZED_PARTIES` and `SECURE_SMTP_CORS_ORIGINS` use JSON arrays for environment values. Compose derives both from the domain. If setting `SECURE_SMTP_CLERK_AUDIENCE`, add a matching audience to the **session token**, preserving `sid` and organization claims; the frontend requests standard session tokens, not a custom JWT template.
5. Rotate credentials formerly present in source/bundles through their issuing systems. Removing a fallback does not rotate database passwords or external credentials. Review historical artifacts separately. This change did not rotate accounts or rewrite git history.
6. Use a fresh `secure_smtp_pilot` database and fresh volumes. The development database has unowned records and may retain a global hostname uniqueness index. Do not silently assign those records to the pilot or drop indexes. An intentional migration must back up, classify ownership, rebuild scoped indexes and verify counts first.
7. Install source dependencies with `.venv/bin/python -m pip install -e '.[dev]'`. In this copied workspace the `pip`/`pytest` launcher shebangs can point to the original project; invoke modules through this copy's Python interpreter.
8. When release blockers are resolved, run `docker compose config --quiet`, then `docker compose up -d --build`. Keep **one backend worker and one backend instance**: process-local admission control, restart recovery and the live broker are not distributed coordination. Horizontal scaling is P2.

No production host, DNS, identity service or database was changed. Starting production remains dependent on configuration and passing the release gates below.

## Recovery rehearsal

Run `.venv/bin/python scripts/rehearse_pilot.py` from the repository root on a machine with the development dependencies, mongod, mongodump and mongorestore. It creates a temporary loopback database and webhook receiver, signs local test sessions, sends an agent batch twice, uploads a fixture capture and downloads a PDF. It restores a MongoDB archive to a different database, checks collection counts and the report bytes, then checks report access after restarting the application lifespan. Repeat the following on the selected host for deployment acceptance.

- Back up MongoDB and the report volume together while writes are paused. Store encrypted backups outside the deployment host; record timestamps, checksums and the corresponding release version. Captures are temporary and normally deleted after analysis.
- Use `mongodump`/`mongorestore` with credentials supplied privately on the host. Restore into a separate test database and separate report volume; never test restoration over the live database.
- Compare owned assessment/session/host counts and download a known completed report. Confirm cross-organization and legacy/unowned records remain inaccessible.
- Restart the API during analysis; the job must become failed with a retry instruction. Re-upload once the service is healthy and verify only the new job is exported.
- Restore the previous release against the test copy before approving rollback. Record achieved recovery time and backup age. No recovery-time or data-loss guarantee is currently claimed.

## Remaining pre-deployment acceptance

Local tests cover the implemented P0/P1 foundation. The following acceptance gates remain open and cannot be marked passed from this workspace:

- Configure Clerk application, verified pilot memberships, domain, HTTPS host, fresh Mongo credentials/database and private secret storage. Rotate credentials through their issuing providers and review old source history.
- Run Compose on the selected host, restore a backup into an isolated copy, and verify container restart/health behavior. Docker is unavailable in this execution environment.
- If used for the finale, provision Neo4j and an approved webhook; verify graph queries and one actual alert delivery.
- Install the collector on a mail server or authorized mirrored source, then verify real SMTP/IMAP/POP3 traffic, disconnect buffering, restart replay, revocation, findings and a scoped report. Do not run capture without network-owner authorization.
- Review the P2 items in CHECKLIST.md before broader commercial rollout.

## Required deployed rehearsal

Use an administrator and an analyst from the pilot organization, plus an unauthorized account. Verify verified sign-in, organization selection, upload and reporting, denied cross-organization requests, denied analyst lab/reset actions, old-key rejection, malformed/oversized capture handling, socket reconnection and backend restart. Connect the agent → generate authorized real traffic → observe findings → export scoped report → disconnect/reconnect agent → verify no duplicate records. Do not substitute synthetic fixture replay for this acceptance test.

## Known limits

- The collector, registration/revocation, telemetry ingestion, bounded durable retry buffer, heartbeat and event deduplication are implemented locally. A real authorized mail-server install and end-to-end traffic rehearsal remain unverified.
- Dashboard transport security, bounded polling, organization-scoped live event notices, stale-data display and replay through the agent outbox are implemented locally.
- Offline JWT verification recognizes revocation/role changes when short-lived tokens expire. Do not configure long session-token lifetimes; immediate provider-side revocation checks are not implemented.
- Capture limits and subprocess deadlines are bounded pilot controls. Interrupted uploads fail visibly and require re-upload; assessment metadata/report retention and deletion are implemented.
- Passive certificate inspection does not perform trust-store/signature/hostname validation. Capture gaps and unobserved TLS fields need further validation against real traffic. An empty findings list is not proof of security.
- The default mail lab is disabled. Optional local lab/replay integration tests require real fixed ports and a disposable MongoDB; they remain skipped in routine tests. The lab is not the continuous production collector.
- Fresh Compose volumes now create a separate application account with readWrite on secure_smtp_pilot only. The backend never receives the root credentials. The initializer and denied administrator/foreign-database operations passed against an authenticated disposable MongoDB. Existing volumes require an explicit backed-up account migration; init scripts do not rerun on existing data. Database ports are not published.
- The local database restore and signed loopback webhook passed. Live Clerk, public HTTPS, external notifications, Neo4j and the deployed browser journey still require acceptance. Local browser access is unavailable in this chat, so rendered browser verification remains open.

## Verification recorded for this implementation

- Backend unit suite: 348 passed, 2 explicit lab integration skips (2026-11-22).
- Frontend logic suite: 22 passed.
- Frontend build and lint pass.
- Boundary tests cover real RSA verification against mocked JWKS, foreign/legacy record denial, scoped job reports, capture framing and size limits, huge sequence gaps, process timeout cleanup, authenticated sockets and organization-targeted broadcasts.

These checks do not constitute deployment approval. See `CHECKLIST.md` for every P0/P1/P2 commitment.

Reference for the identity contract: [Clerk manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification), [Clerk session claims](https://clerk.com/docs/guides/sessions/session-tokens), and [PyJWT verification](https://pyjwt.readthedocs.io/en/latest/usage.html).
