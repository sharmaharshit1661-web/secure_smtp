# Installing on a private network

Choose one installation per host or VM. The examples assume Linux, Docker Engine and Compose 2.24.4 or later. Give the host a stable LAN IP and point an internal DNS name at it. Allow TCP 443 from pilot users and collectors. Allow TCP 80 only if HTTP redirection is wanted. Keep WAN forwarding disabled. Both variants bind to the selected interface and use Caddy's internal certificate authority.

## Private installation using Clerk

Copy `.env.example` to a mode-0600 `.env`. Set PILOT_DOMAIN, PILOT_LAN_IP, separate fresh MongoDB administrator and application credentials, the real Clerk publishable key, issuer and pilot organization ID. Use your organization’s domain and configure that HTTPS origin in Clerk. The clients need access to Clerk and the backend needs its signing keys.

```sh
docker compose -f docker-compose.yml -f docker-compose.private.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.private.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.private.yml cp edge:/data/caddy/pki/authorities/local/root.crt pilot-root.crt
```

Distribute the public root certificate using your organization’s trusted channel. Install it in clients’ trust stores. Invite pilot members by email through Clerk. Once a member accepts the invitation and signs in, select the pilot organization to open the dashboard.

## Disconnected installation using Keycloak

On a connected machine with the target CPU architecture, run `scripts/package_offline.sh /path/to/new-bundle`. Transfer the entire directory over a trusted channel. The bundle contains application and infrastructure images, realm configuration and the Compose file. On the target, from that directory:

```sh
sha256sum -c SHA256SUMS
docker load -i images.tar
umask 077
cp .env.offline.example .env
```

Edit .env locally. Set the actual internal hostname and LAN IP and generate distinct strong passwords for the MongoDB administrator (MONGO_ROOT_PASSWORD), application account (SECURE_SMTP_MONGO_PASSWORD), PostgreSQL and the initial Keycloak administrator. Use different MongoDB usernames (MONGO_ROOT_USER and SECURE_SMTP_MONGO_USER). The application authenticates against secure_smtp_pilot with readWrite only; initialization runs only on fresh volumes. Back up existing deployments and migrate their accounts deliberately; changing environment values does not change users already stored in MongoDB. Start the images and retrieve the public CA certificate:

```sh
docker compose -f docker-compose.offline.yml config --quiet
docker compose -f docker-compose.offline.yml up -d --no-build --pull never
docker compose -f docker-compose.offline.yml cp edge:/data/caddy/pki/authorities/local/root.crt pilot-root.crt
```

Install the public certificate on trusted clients. At `https://YOUR-HOST/id/admin/`, use the bootstrap administrator to create a permanent identity administrator, then retire the bootstrap account. Select the **pilot** realm. Create a user, set a temporary password, and assign the **secure-smtp** client role **analyst** or **admin** under Role mapping. Give the user the internal URL, username and temporary password through your approved channel. On their first visit they sign in on the local Keycloak page, change the temporary password and enter the dashboard. Users without an application role cannot access assessment APIs.

The offline application uses local identity, scoring, template explanations, reports and browser assets. Leave optional external integrations disabled. Back up PostgreSQL (users, roles and signing keys), MongoDB, generated reports, and Caddy data (including its CA private key) securely. Trust only the public CA certificate on clients.

## Collector and acceptance

Provision a collector from Monitoring & operations. On an authorized Linux mail server or mirror, load the backend image from the bundle, install the public root at /etc/secure-smtp/pilot-root.crt and place the one-time agent credential in /etc/secure-smtp/agent.credential. Use mode 0600 and match credential ownership to the collector process. For a Linux host where capture requires root, run the collector container as root with only NET_RAW, a read-only filesystem, and a dedicated writable queue volume. For example, with the root-owned 0600 credential and the correct interface:

```sh
docker run -d --name secure-smtp-agent --restart unless-stopped --network host \
  --no-healthcheck --user 0:0 --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \
  --read-only -v /etc/secure-smtp:/etc/secure-smtp:ro -v smtp-agent-state:/state \
  -e SSL_CERT_FILE=/etc/secure-smtp/pilot-root.crt secure-smtp-backend:pilot \
  secure-smtp-agent --authorized --interface YOUR-INTERFACE --server https://YOUR-HOST \
  --credential-file /etc/secure-smtp/agent.credential --state /state/queue.sqlite
```

For the connected private build, tag its backend image as secure-smtp-backend:pilot before distributing it. Keep the lab disabled. For offline acceptance disconnect WAN while retaining LAN DNS and time synchronization. From a fresh browser sign in as an analyst, observe the collector heartbeat, generate authorized mail traffic, inspect a session and download its PDF. Check that an analyst cannot provision collectors. Restart the services and repeat sign-in and report download. These checks require the actual installation.

## Local graph integration

The offline bundle also includes the Neo4j image. For either installation, set a unique GRAPH_PASSWORD in the private .env file, then append `-f docker-compose.graph.yml` to the compose file arguments before the command. The backend connects to Neo4j on the private network. Include graph_data in backups. To send alerts while disconnected, configure the webhook URL and signing secret for a receiver reachable on your LAN.
