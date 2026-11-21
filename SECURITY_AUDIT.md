# Security and functionality audit — 22 November 2026

## Release assessment

The project has a tested single-organization pilot path. This review is a code and
local-runtime assessment, not independent penetration testing, certification or a
claim that every production configuration is secure. No remote deployment was
performed or verified. Changes must be redeployed to affect the hosted service.

## Fixed findings

| Finding | Change | Evidence |
|---|---|---|
| Arbitrary credentials, fake social sign-in and forged localStorage granted dashboard access | Removed simulated authentication and self-provisioned roles. Local login verifies a salted PBKDF2 hash, issues expiring HttpOnly cookies and revokes sessions on logout. Unconfigured login fails closed. | Wrong-password, unknown-user, forged-cookie, expiry, CSRF, logout and browser-storage regressions |
| Browser bundle exposed the shared backend API key | Removed VITE_API_KEY from code/build configuration. Local browser requests use cookies; Clerk requests use signed session tokens. Machine keys remain a separate header-based interface. | Browser API/report flow; bundle check; request authentication tests |
| WebSocket allowed unauthenticated development access | Require short-lived, single-use connection tickets or a machine header key. Validate browser origin and reconnect for authorization after 60 seconds. | Missing/forged/replayed ticket rejection and live ping test |
| Report generation queried every assessment | Tag sessions with job_id; export only matching sessions and recompute host totals for that assessment. Existing reports require regeneration. | Report scoping regression and real upload/export browser test |
| HTML/PDF interpreted attacker-controlled report fields as markup | Enable HTML autoescaping and escape PDF interpolated fields | HTML injection regression; PDF export workflow |
| Rate limiter trusted raw X-Forwarded-For | Use the server-normalized client address; configure trusted proxies at deployment | Repeated login attempts with changing forwarding headers remain limited |
| Mail dispatcher accepted arbitrary network targets | Require explicitly allowed IP literals and permitted mail ports. Lab actions are configuration-gated; DNS targets are rejected. | Metadata, encoded-IP, IPv6, hostname and unauthorized target rejection |
| Certificate chain validity relied on issuer names | Verify observed issuer signatures cryptographically. UI no longer equates observed checks with CA trust. | Matching-name/wrong-signing-key regression |
| Alert defaults ignored configured thresholds; lowercase findings disappeared from summaries | Respect configured severity/risk settings, normalize severity and avoid logging webhook URLs | Threshold tests and real HTTP delivery to a temporary localhost receiver |
| Crafted TCP sequence gaps could allocate gigabytes | Bound reconstructed directions to 16 MiB; stream PCAP parsing with packet, stream and payload limits; add IPv6 extraction | Allocation-limit and IPv6 tests |
| Tests used the developer's configured database | Force test configuration to a disposable localhost database and temporary report/upload directories | Full suite against isolated MongoDB on port 27029 |
| Launcher killed unrelated processes and seeded data automatically | Refuse occupied ports, make seeding opt-in, bind development HTTP to localhost, require configured login | Shell syntax check and source review |
| Dashboard showed lab ports as online even when stopped | Bind labels to backend status, refresh status, distinguish telemetry connection from mail-lab operation and remove invented clearance/certification labels | Browser check with lab disabled |
| Public health response disclosed database topology | Return minimal service/database health only | Health endpoint regression |
| Known dependency advisories | Update both npm lockfiles; raise Python dependency security floors and patch the local environment | npm and pip-audit follow-up scans |

## Verification results

- Full backend suite: **198 passed**, with two upstream deprecation warnings.
- Frontend production build and lint: passed.
- Browser on isolated local services: forged localStorage rejected; wrong password
  rejected; correct login and refresh succeeded; cookie was HttpOnly; a real PCAP
  upload completed; JSON/PDF exports succeeded; logout revoked access; no runtime
  browser errors observed. Desktop and mobile screenshots inspected.
- Real localhost SMTP lifecycle, synthetic scenario pipeline and signed webhook
  delivery were exercised. No mail or notification was sent to an external party.
- npm audits: zero known vulnerabilities after compatible updates (workspace and
  standalone frontend lockfiles).
- Python installed-package audit: zero known vulnerabilities after updates.
  The pre-existing optional Streamlit installation was updated for compatibility
  with patched Pillow; Streamlit is not an application dependency.
- Python dependency consistency, compile checks, focused lint, diff whitespace and
  launcher shell syntax checks passed.
- The generated local pilot account was verified without printing its password.

VERDICT: PASS — scoped local regression checks; deployment readiness remains conditional.

## Operating the pilot

### Local account

The operator is provisioned in the ignored `.env`; only its password hash is
stored there. The generated password is in `output/private/local-operator.txt`
with owner-only permissions. Save it securely and delete that file when no longer
needed. It is excluded from Git and Docker build context.

To rotate/reprovision from the repository root:

```sh
PYTHONPATH=src .venv/bin/python scripts/provision_local_operator.py
```

Restart frontend and backend afterward. This configures local same-origin login
and clears Clerk/frontend remote API overrides in `frontend/.env.local`. Configure
MongoDB separately; provisioning does not create or alter database accounts.
Run `./start_demo.sh` only after database connectivity is configured. Set
`SECURE_SMTP_SEED_DEMO=true` only for an isolated demonstration database.

Use one backend worker: local sessions, connection tickets and rate-limit state
are in memory. Restart logs users out. Production requires HTTPS for Secure
cookies and an exact CORS origin allowlist. Keep the API and UI on the same origin
for local-cookie authentication. Do not expose the Vite development server.

### Clerk option

Set the frontend publishable key, `SECURE_SMTP_CLERK_ISSUER`, exact frontend origins
in `SECURE_SMTP_CORS_ORIGINS`, and `SECURE_SMTP_CLERK_ORG_ID` for a restricted pilot.
Remove the local frontend override when switching modes. The backend checks RS256
signatures using issuer JWKS, issuer, expiry/not-before, authorized party, pending
status and the configured organization. Invalid JWTs never fall back to API keys.
Cryptographic checks were tested with generated signing keys; a real Clerk tenant
login/invitation was not tested. Provider signup/invitation policy needs configuration.

### Machine clients and mail lab

Use a unique service API key of at least 32 characters in an Authorization or
X-API-Key header; do not put credentials in URLs. Production rejects empty/default
or short service keys and refuses disabled authentication. Rotate the old key in
any already-deployed environment because prior frontend builds exposed it.
Mail lab actions require `SECURE_SMTP_ENABLE_LIVE_LAB=true`. Add only authorized
IP literals to `SECURE_SMTP_DISPATCH_ALLOWED_IPS`; the default allows loopback.
The dispatcher intentionally uses insecure TLS for controlled attack scenarios;
it is not a production mail-sending client.

### Repeatable tests

Start a disposable `mongod` bound to `127.0.0.1:27029` with a fresh temporary dbpath,
then run `.venv/bin/python -m pytest -q`. The suite uses database
`secure_smtp_tests` and localhost SMTP ports 2525–2528; it never targets the `.env`
database. Stop the disposable MongoDB after testing. `npm run build --prefix
frontend` and `npm run lint --prefix frontend` verify the UI build.

## Remaining limits and work

1. Local login provides one privileged pilot operator, not multiple users, role
   separation or tenant isolation. Clerk users share the configured pilot data.
   Do not onboard unrelated organizations into this deployment.
2. Neo4j, a continuous external capture agent and offline Keycloak are not
   implemented. Synthetic replay and the local mail lab are not enterprise passive
   network monitoring. Public HTTPS, Docker images, backup restoration and restart
   of a hosted deployment have not been exercised here (Docker was unavailable).
3. Background analysis is in-process, without a durable queue, global worker
   quotas or crash recovery. Capture limits reject oversized inputs; they do not
   constitute a full hostile-input parser sandbox. TCP wraparound/reused flows and
   full trust-store/hostname/revocation validation need further work.
4. Reports are job-scoped after this change; historical stored reports can contain
   combined data. No automatic retention/deletion or complete access audit log is
   implemented. Captures can contain sensitive plaintext even though reports focus
   on metadata; protect uploads and establish a retention policy.
5. Alert delivery now honors settings and is tested locally, but persistent retries,
   deduplication and delivery-status UI remain missing. External webhook operation
   is unverified. Cloud copilot output/provider availability is unverified and
   requires an explicit data-sharing decision for sensitive telemetry.
6. Scoring is rule-weighted by default. SHAP calibration is optional, and anomaly
   models use uploaded batches. Do not claim production detection accuracy,
   confirmed MITM attribution from plaintext alone, or regulatory certification.
7. Dependency scans describe known advisories at check time, not proof of absence
   of vulnerabilities. Continue independent security review and load testing before
   broad market deployment. Existing deprecation warnings should be addressed in
   a separate compatibility update.
