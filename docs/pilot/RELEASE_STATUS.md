# Vercel / Render release preparation — 22 November 2026

## Measured checks

- Backend: 355 tests passed, two dependency deprecation warnings.
- Frontend: 25 logic tests passed; lint and production build passed.
- Isolated runtime: API ingestion, scoped reports, signed local webhook, application restart and independent MongoDB restoration passed.
- Render blueprint and Vercel configuration validated against published schemas. Vercel's current schema has a metaschema incompatibility with Python jsonschema's schema precheck; instance validation passed using Draft7Validator directly.
- Git diff whitespace check passed.

## Changes in this release preparation

Corrected CI to use the repository-root npm lockfile and Node 22; added frontend tests to CI. Isolated the default CORS test from developer-specific Clerk environment files without widening the actual CORS allowlist. Excluded local Clerk state, environment files and temporary artifacts from deployment upload contexts. The selected Clerk development application is linked and the local frontend key is restored; local backend issuer configuration must be loaded by restarting the backend. No production key migration was performed.

## Deployment files

- vercel.json: repository-root frontend workspace build, static output, SPA route fallback.
- render.yaml: Docker backend, single instance, health probe, persistent report disk and prompted secrets. The selected Standard plan and disk incur provider charges; no resources were created here.
- scripts/check_deployment.py: checks basic environment shapes without printing secrets. A passing result does not prove live identity or database connectivity.
- VERCEL_RENDER.md: exact platform settings and acceptance procedure.

## Outstanding requirements

Supply actual Vercel and Render service URLs. Provision hosted MongoDB with TLS, restricted application permissions and network access for Render. Add database credentials only through the hosting secret settings. Set frontend VITE_API_BASE and Clerk publishable key; set backend issuer, exact-origin CORS and authorized parties. Configure Clerk Open access and complete production instance/domain setup before a production launch; development Clerk is suitable only for staging/development validation.

Docker is unavailable locally, so the Linux container and mounted report disk permissions still need hosted verification. Local browser access remains unavailable in this chat. Verify real registration/login, two-user data isolation, capture upload/PDF download, nested-route reload, logout and backend restart on the deployed URLs. Neo4j is optional and must be separately provisioned and validated if enabled. Collector HTTPS/proxy behavior and authorized traffic require a real collector test. Ingress abuse controls and capacity remain release gates for public use.

Status: repository prepared for configured staging deployment; production approval withheld until the live acceptance checks pass. No deploy, push, account purchase or provider-secret update was performed.
