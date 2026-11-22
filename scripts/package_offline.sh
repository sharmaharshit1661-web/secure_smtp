#!/usr/bin/env bash
# Run on a connected Docker builder of the same CPU architecture as the target.
set -euo pipefail
cd "$(dirname "$0")/.."
dest=${1:?Supply a new output directory outside the project}
mkdir "$dest"
dest=$(cd "$dest" && pwd)
# Compose validates settings even for build. These placeholders never run a service.
export PILOT_DOMAIN=build.invalid PILOT_LAN_IP=127.0.0.1 SECURE_SMTP_MONGO_USER=build
export SECURE_SMTP_MONGO_PASSWORD=build-only IDENTITY_DB_PASSWORD=build-only IDENTITY_BOOTSTRAP_PASSWORD=build-only
export MONGO_ROOT_USER=build-admin MONGO_ROOT_PASSWORD=build-only
compose=(docker compose --env-file /dev/null -f docker-compose.offline.yml)
"${compose[@]}" config --quiet
"${compose[@]}" pull edge mongodb identity identity-db
"${compose[@]}" build frontend backend
images=()
while IFS= read -r image; do images+=("$image"); done < <("${compose[@]}" config --images)
docker pull neo4j:5.26-community
images+=(neo4j:5.26-community)
docker save -o "$dest/images.tar" "${images[@]}"
mkdir -p "$dest/docker/offline"
cp docker/offline/{Caddyfile,pilot-realm.json} "$dest/docker/offline/"
cp docker/mongo-init.js "$dest/docker/"
cp docker-compose.offline.yml docker-compose.graph.yml .env.offline.example docs/pilot/NETWORK.md "$dest/"
(cd "$dest" && shasum -a 256 images.tar docker-compose*.yml docker/mongo-init.js docker/offline/* > SHA256SUMS)
