#!/usr/bin/env bash
# Stop the running Honeypot Shelf stack without removing anything — containers,
# volumes (your data), and networks are all left in place, just not
# running. Auto-detects whether the bundled Caddy reverse proxy and/or the
# VPN sidecar are part of this deployment (same detection
# scripts/upgrade.sh uses, by each container's own Compose service label —
# nothing to pass by hand, works whichever of the two (or neither, or
# both) you're running):
#
#   ./scripts/stop.sh
#
# Bring it back up with ./scripts/start.sh — that one auto-detects the same
# way, so it always matches whatever this stopped, even months later.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the Honeypot Shelf checkout." >&2
  exit 1
fi

compose_files=(-f docker-compose.yml)
if docker ps \
    --filter "label=com.docker.compose.project=honeyhive" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> Bundled Caddy reverse proxy detected — including docker-compose.caddy.yml."
  compose_files+=(-f docker-compose.caddy.yml)
fi
if docker ps \
    --filter "label=com.docker.compose.project=honeyhive" \
    --filter "label=com.docker.compose.service=vpn" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> VPN sidecar detected — including docker-compose.vpn.yml."
  compose_files+=(-f docker-compose.vpn.yml)
fi

echo "==> Stopping the stack..."
docker compose "${compose_files[@]}" stop

echo
echo "Stopped. Nothing was removed — your data is untouched. Bring it back up with:"
echo "  ./scripts/start.sh"
