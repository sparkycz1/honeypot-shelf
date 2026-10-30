#!/usr/bin/env bash
# Start a Honeypot Shelf stack previously stopped with ./scripts/stop.sh (or
# `docker compose stop`). Starts what COMPOSE_PROFILES in .env names (the
# bundled database and, if chosen, Caddy) together with the app, and
# auto-detects whether the VPN sidecar was part of that deployment, from
# the stopped-but-still-present container's own Compose service label
# (same detection scripts/upgrade.sh/stop.sh use), so you never have to
# remember or pass which `-f` files by hand:
#
#   ./scripts/start.sh
#
# This only starts what's already there — it doesn't build images, apply
# migrations, or change .env. For a first-time deploy, use
# scripts/setup.py instead; to update to a new release, use
# scripts/upgrade.sh.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the Honeypot Shelf checkout." >&2
  exit 1
fi

# Which services belong to this stack (database, Caddy) is
# COMPOSE_PROFILES in .env; an .env from before 0.86.0 gets it here.
# shellcheck source=scripts/compose_profiles.sh
. scripts/compose_profiles.sh
ensure_compose_profiles
compose_files=(-f docker-compose.yml)
if docker ps -a \
    --filter "label=com.docker.compose.project=honeypotshelf" \
    --filter "label=com.docker.compose.service=vpn" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> VPN sidecar detected — including docker-compose.vpn.yml."
  compose_files+=(-f docker-compose.vpn.yml)
fi

if ! docker ps -a \
    --filter "label=com.docker.compose.project=honeypotshelf" \
    --format '{{.Names}}' | grep -q .; then
  echo "error: no existing Honeypot Shelf containers found — nothing to start." >&2
  echo "       First time here? Use: python scripts/setup.py" >&2
  exit 1
fi

echo "==> Starting the stack..."
docker compose "${compose_files[@]}" start

echo "==> Status:"
docker compose "${compose_files[@]}" ps

echo
echo "Done. If anything looks wrong: docker compose logs -f web"
