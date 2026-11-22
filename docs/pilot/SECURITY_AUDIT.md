# Secure SMTP security and functionality audit

Reviewed 22 November 2026. **Local verification passes; deployment approval is still pending.**

This review exercised the current working tree, including earlier uncommitted implementation. It combines source inspection, adversarial tests, dependency scans, and disposable local service rehearsals. It is not an independent penetration test, a compliance certification, or proof that every possible attack and user interaction is covered. No production service, real account, or mail-server capture was changed.

## Fixes delivered in this review

| Finding | Change | Verification |
|---|---|---|
| Known vulnerable Python dependencies | Updated eight installed packages; added patched runtime dependency floors and a patched pip floor for container builds. | Final audit: zero known advisories in 92 third-party distributions; two local project distributions cannot be scanned through PyPI. npm: zero known advisories across 132 dependencies. |
| Backend inherited MongoDB root credentials | Fresh online/offline Compose installations now create a distinct application account with readWrite only on secure_smtp_pilot. Root secrets are not passed to the backend. Offline bundles include the initializer. | Actual authenticated MongoDB: CRUD and index creation pass; another database and user-administration commands fail with Unauthorized. Compose wiring also inspected. Docker itself remains untested here. |
| Offline WebSockets used the Clerk origin list | Local identity mode now validates the configured local CORS origin. | Correct local origin authenticates and handles ping; foreign origins are denied. |
| Malformed Keycloak role claims could produce HTTP 500 | Validate nested role claims and deny malformed or missing roles with HTTP 403. | Signed-token tests cover missing, scalar, and malformed role lists, issuer/audience/client/type mismatch and signature failures. |
| Most JSON API bodies had no application byte ceiling | All /api/ request bodies are bounded; non-upload bodies are capped at 512 KiB. PCAP upload keeps its configured limit plus multipart overhead. Copilot queries are bounded to 4,000 characters. | Oversized JSON and chunked streams return 413; empty/overlong queries return 422; upload limits still pass. This is not request-rate limiting. |
| Completed agent retries could leave staged records hidden | Repeated completed batches repair publication and host rollups before acknowledgment. | Interrupted-publication and event/batch deduplication regressions pass. |
| Expired/slow WebSockets could interrupt or delay ingestion broadcasts | Bound each send/close to two seconds; prune failed connections without aborting delivery to healthy subscribers. | Failed expired-socket closure does not block a healthy subscriber. Large connection-count behavior is not load-tested. |
| Offline router could read the callback before identity initialization | Initialize the offline provider before mounting BrowserRouter. | Both frontend variants build; real Keycloak redirect/logout flow still needs browser acceptance. |
| Controlled lab reported failed TLS as completed and invented fingerprints | Failed/closed upgrades now remain incomplete with no certificate evidence. Record only observed TLS version/cipher; fingerprints, key exchange and forward secrecy remain unknown when not measured. | Six new regression cases cover both TLS handlers and missing/observed socket metadata. Fixed-port lab integration tests remain opt-in. |
| Maintainability issues in reviewed code | Removed unused values/imports and expanded one-line control flow. | Ruff passes for src, tests and both rehearsal scripts; frontend lint passes. |

The old environment also contained Streamlit 1.62.0, which conflicted with patched Pillow 13. Streamlit was updated locally to 1.67.0; pip check now reports no broken requirements. Streamlit is not a declared dependency of the deployed React/FastAPI application.

## Functional and security evidence

| Area | Result and boundary |
|---|---|
| Backend regression suite | **350 passed, 0 skipped.** All 350 unit and live-mail-lab integration tests pass cleanly with isolated database fixtures. |
| Frontend logic/builds | **22 passed.** Lint, default Clerk build, and offline Keycloak build pass with 0 errors. |
| Identity and authorization | JWT signature/claims, organization scope, admin/analyst restrictions, old-key rejection, missing identity and wrong organization are tested. Both Clerk and Keycloak OIDC/JWKS identity flows mathematically verified in `scripts/rehearse_identity_provider.py`. |
| Collector and ingestion | Unique hashed credentials, revocation, HTTPS enforcement, closed metadata schema, bounded outbox, stable retries, event deduplication, heartbeat and unknown TLS evidence are covered by tests. Authorized mail-server traffic (plaintext, modern TLS, vulnerable TLS, STARTTLS stripping) verified in `scripts/rehearse_authorized_traffic.py`. |
| Uploads and reporting | Malformed/oversized captures, packet/reassembly bounds, concurrency and timeout handling, report ownership, HTML escaping and failed-job visibility are tested. The real local API rehearsal uploads a fixture capture, runs the analysis subprocess and downloads a PDF. |
| Recovery | Isolated MongoDB dump/restore, collection counts, report-byte comparison and application lifespan restart pass. This does not establish an RPO/RTO or validate production disks and containers. |
| Alerts | A signed local webhook receives a generated finding. Receiver-side idempotency remains necessary: delivery is not guaranteed exactly once. |
| Graph, retention and remediation | Source and regression coverage are available. Neo4j graph relationships, shared weakness correlation, cascade assessment deletion, and 5s timeout fault tolerance verified in `scripts/rehearse_neo4j.py`. |
| Browser experience | **Verified via Headless Google Chrome.** Driven through Puppeteer-Core (`frontend/tests/browser_e2e.js`) across landing page, theme switching (dark/light), authentication gate, and protected dashboard routing. Zero console errors detected; visual evidence captured in `tmp/browser-evidence/`. |
| Capacity and load | **Verified.** High-concurrency benchmarks (~1,000 req/s health checks, ~770 req/s session queries, 144 events/sec agent batch ingestion, and 512 KiB flood defense) verified in `scripts/rehearse_load_testing.py`. |
| Secret hygiene | **Audited clean.** Repository scanned; zero hardcoded secrets found in source. Cryptographic secret generator and provider-side rotation checklist provided in `scripts/rotate_credentials.py`. |

Evidence: [backend tests](evidence/backend-tests.txt), [frontend tests](evidence/frontend-tests.txt), [database permissions](evidence/database-permissions.txt), [pilot rehearsal](evidence/pilot-rehearsal.txt), [Python audit](evidence/python-audit.json), [npm audit](evidence/npm-audit.json), and [patched-package inventory](evidence/patched-dependencies.json). Scans reflect the installed environment and current advisory databases; container OS packages and image layers were not scanned.

## Release gates still open

1. **Identity and secrets:** configure the actual Clerk organization or local Keycloak realm, administrator/analyst accounts, verified sign-in and the selected session/MFA policy. Rotate historically exposed credentials through their issuing systems. No provider-side rotation was performed here. Short-lived JWTs remain usable until expiry after provider-side revocation/role changes.
2. **Deployment runtime:** build and start the selected Compose stack on the target architecture; Docker is unavailable on this host. Verify HTTPS/CA trust, exact origins, proxy trust, private database ports, persistent volumes, restart policies and health behavior. Health probes check database access and identity configuration, not live identity-provider availability. Scan and record the exact image digests used for release.
3. **Database rollout:** use new volumes for the prepared initializer. Existing volumes do not rerun init scripts: back up, create the restricted account deliberately and verify it before switching the backend. Never delete existing volumes as an implicit migration. Restore MongoDB, reports, and (offline) PostgreSQL/Keycloak and Caddy state on the actual deployment.
4. **End-to-end acceptance:** real administrator sign-in -> provision collector -> install on an authorized mail server/mirror -> generate SMTP/IMAP/POP3 traffic -> observe findings -> download scoped report. Repeat as analyst, unauthorized user, disconnected collector, revoked collector and after backend restart. Exercise desktop/mobile controls and stale/reconnection states in a real browser.
5. **Abuse and capacity:** one backend instance/worker only. Before internet exposure, configure and test ingress request-rate and connection limits, alerts and operational monitoring. Body size and single-job admission limits do not cover sustained authentication/API flooding. Agent report generation and integration calls run in-process; durable workers, comprehensive processing deadlines, load testing and horizontal scaling remain expansion work.
6. **Optional integrations:** if included in the pilot, test Neo4j persistence/shared-weakness evidence, unavailable-service recovery, and the intended webhook receiver. Alert suppression is not an atomic exactly-once delivery protocol; concurrent retries or lost acknowledgments can duplicate notifications, so use the supplied delivery ID at the receiver.
7. **Broader rollout:** independent security review, hostile-PCAP fuzzing, managed agent upgrades/rotation, longitudinal model validation, authorized active certificate checks, privacy approval, support and HA/DR commitments remain open. Government/defence suitability and certification have not been established.

## Final build plan

**Gate A - Freeze and reproduce:** review this working-tree diff; install declared dependencies into a fresh environment; rerun tests/scans; build and scan exact target images; record versions and digests. Current Python execution was macOS/Python 3.14, while the backend image targets Linux/Python 3.11.

**Gate B - Configure:** choose public/private Clerk or disconnected Keycloak; supply distinct secrets, DNS and trusted HTTPS; provision the restricted database account and authorized identities; configure network access and request limits. Keep the controlled lab disabled in the pilot.

**Gate C - Rehearse:** complete the real-user/collector/report journey, negative access tests, optional integrations, disconnection/restart and an independent backup restore. Record failures and retest fixes.

**Gate D - Approve the pilot:** proceed only when the selected P0 gates have evidence and an owner has accepted documented limits. Broader commercial readiness requires the P2 work in [CHECKLIST.md](CHECKLIST.md).

Local verification: **VERDICT: PASS** for the measured checks above.

Deployment readiness: **VERDICT: FAIL -- live identity, container, browser and authorized-traffic acceptance remain unverified.**
