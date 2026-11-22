# Deploy with Vercel and Render

This is a prepared deployment configuration, not an executed deployment. Actual Clerk keys, service URLs and a hosted MongoDB database are still required. Do not announce production readiness until the acceptance checks below pass.

## 1. Clerk and database

Use one real Clerk application for both frontend and backend. Enable Open access mode and your intended verification/sign-in methods. For a production custom domain use Clerk's production instance and complete its domain setup. A development instance can support a staging demonstration with its development limitations.

Create a MongoDB deployment (for example Atlas). Create an application database user limited to readWrite on secure_smtp_pilot. Permit the Render service's outbound IP ranges using the database network controls. Obtain the TLS connection URI; store it only in Render. Do not place it in a VITE variable or source control.

## 2. Vercel frontend

Import the repository with Root Directory set to the repository root (not frontend). vercel.json selects npm ci, the frontend workspace build, frontend/dist, and SPA routing.

Set these Vercel build environment variables:

| Variable | Value |
|---|---|
| VITE_CLERK_PUBLISHABLE_KEY | The publishable key of your real Clerk application |
| VITE_AUTH_PROVIDER | clerk |
| VITE_API_BASE | Exact Render HTTPS service origin, with no trailing slash |

Get the stable Vercel production domain. Do not authorize arbitrary preview domains. Build environment changes require a new frontend deployment. Until the Render service exists you can reserve the frontend domain, then set its URL and redeploy.

## 3. Render backend

Import render.yaml as a Blueprint, or create a Docker web service using Dockerfile.backend and repository-root build context. The blueprint requests a paid Standard service and a 1 GB persistent disk; review the current quoted price before creating resources. The standard instance provides room for the analysis/PDF dependencies. Smaller instance capacity is not verified.

Set prompted values privately:

| Variable | Value |
|---|---|
| SECURE_SMTP_CLERK_ISSUER | Exact Clerk HTTPS session issuer from the same application |
| SECURE_SMTP_CLERK_AUTHORIZED_PARTIES | JSON array containing the exact Vercel HTTPS origin |
| SECURE_SMTP_CORS_ORIGINS | The same exact-origin JSON array |
| SECURE_SMTP_MONGO_URI | Authenticated TLS MongoDB URI |

Example origin array: ["https://YOUR-PROJECT.vercel.app"]. Replace the example with the actual domain. Public personal registration does not require SECURE_SMTP_PILOT_ORG_ID. Set that only if enabling an existing shared pilot organization.

Keep one backend worker and one instance. Keep the mail lab disabled. /api/health must return HTTP 200. The report volume is /app/storage; using only ephemeral storage will lose PDFs on restart/deploy. Configure backups for MongoDB and the report disk. The source includes a persistent-directory ownership preparation step, but verify write access on the actual mounted Render disk.

## 4. Connect and smoke-test

Set VITE_API_BASE to the actual Render origin, then redeploy Vercel. Configure the stable frontend domain in Clerk. Visit /sign-up, create and verify a new account, and confirm dashboard access. Register a second account and confirm private results remain isolated. Upload a small authorized capture, wait for completion, download a PDF and reload a nested route directly. Verify logout/login, expired sessions, invalid uploads and backend restart. Check browser console/network failures and mobile layouts.

## Neo4j and collectors

To enable hosted Neo4j, supply SECURE_SMTP_NEO4J_URI (prefer encrypted neo4j+s), SECURE_SMTP_NEO4J_USER and SECURE_SMTP_NEO4J_PASSWORD privately in Render. The URI is the Bolt/Neo4j connection address, not the browser-console URL. The service account needs permission to create the graph constraints and read/write evidence. Verify synchronization and shared-weakness queries before promising this feature. docker-compose.graph.yml is for a Docker host; it is not imported by Render automatically.

Personal registrants are members and cannot provision agents. Shared-pilot administrators can provision agents when the pilot organization is configured. Run collectors on authorized mail servers/mirrors, not Vercel. Verify HTTPS/proxy handling on the actual Render service before agent acceptance; do not weaken the HTTPS check to work around a failed connection.

## Release status

Local tests/builds and isolated recovery pass. Actual Vercel deployment, Render container execution, real Clerk account registration, persistent disk permissions, hosted MongoDB/Neo4j connectivity and browser acceptance remain unverified. The available browser tool cannot access local pages in this chat. These are deployment acceptance gates, not issues a successful compile can close.

Official references: https://render.com/docs/blueprint-spec , https://render.com/docs/disks , https://vercel.com/docs/frameworks/frontend/vite , https://clerk.com/docs/guides/secure/restricting-access .
