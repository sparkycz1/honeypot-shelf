# syntax=docker/dockerfile:1

# --- Stage 1: build the virtualenv with uv -----------------------------------
FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS builder

# Official static uv binary — no need to pip-install it into the image.
# Pinned to an exact version (same reasoning as Postgres/Redis/Caddy) —
# `:latest` would silently pick up a new uv release, and thus a possibly
# different dependency resolver/behavior, on every rebuild.
COPY --from=ghcr.io/astral-sh/uv:0.12.17 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Manifests first — the dependency layer is cached separately from the source code.
COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

COPY app ./app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# --- Stage 2: minimal runtime image ------------------------------------------
FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS runtime

# The netbird CLI/daemon binary — pinned to an exact version (same
# reasoning as Postgres/Redis/Caddy/uv above: bumped deliberately, not
# silently picked up on every rebuild). This one specifically is NOT
# "always latest at build time" like wireguard-tools below, and that's
# deliberate, learned the hard way: NetBird persists this peer's identity
# (private key, registration) in `/etc/netbird` across restarts/upgrades,
# and a newer client version can change that local state's format enough
# that the new binary can't read the old peer's identity back — from the
# NetBird management server's point of view that's indistinguishable from
# a *brand new device*, which needs a fresh (unused) setup key to
# register, not the one already spent on the original registration
# months ago. `scripts/upgrade.sh` used to force a fresh NetBird binary
# on every single upgrade (via CACHE_BUST below) specifically to always
# track the latest release — which is exactly what caused that "setup key
# is invalid" loop on nearly every upgrade in practice. Bump
# `NETBIRD_VERSION` by hand, in the same round of work as any other
# pinned-dependency bump, and expect that (like a Postgres/Redis major
# version bump) it may need re-registering with a fresh setup key once,
# deliberately — not on every unrelated upgrade.
ARG NETBIRD_VERSION=0.78.2

# Installed straight from its GitHub release tarball, not the `.deb`
# (whose postinst script tries to install and start a SysV init service —
# nothing this image ever has, since it only ever runs a single
# foreground process, so that install would fail the build for no
# benefit; nothing here needs the systemd unit the `.deb` would set up
# either). Never run inside `web`/`worker` themselves (that needs
# CAP_NET_ADMIN/`/dev/net/tun`, which this image's containers deliberately
# don't have; see app/services/netbird.py's module docstring) — this lets
# `web` issue `netbird up/down/status` against the optional
# `docker-compose.vpn.yml` sidecar's daemon over a shared socket volume
# instead. Harmless to have installed even when that overlay isn't used —
# the CLI just fails with a clear "can't reach the daemon" error, same as
# any other optional integration (LDAP/OIDC/syslog) left unconfigured.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL \
        "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_linux_amd64.tar.gz" \
        | tar xz -C /usr/local/bin netbird \
    && chmod +x /usr/local/bin/netbird \
    && rm -rf /var/lib/apt/lists/*

# CACHE_BUST alone (an ARG whose *value* changes) is what actually forces
# Docker to re-run the layer below instead of reusing a months-old cached
# one — `docker compose build` on an unchanged Dockerfile would otherwise
# happily keep serving whatever wireguard-tools version was cached from
# the very first build forever. `docker-compose.yml` sets this from a
# `CACHE_BUST` shell variable; `scripts/upgrade.sh` exports a fresh one
# (the current date) before every build, same mechanism as `GIT_COMMIT`
# below. Defaults to "unknown" for a plain `docker build` with nothing
# passed — cache reuse in that case is the same tradeoff a bare
# `docker build` already makes for every other layer. Deliberately NOT
# applied to the NetBird install above any more — see NETBIRD_VERSION's
# own comment for why that one is pinned instead.
ARG CACHE_BUST=unknown

# `wg`/`wg-quick` (plus `iproute2`'s `ip` command, which `wg-quick` shells
# out to for the interface/route setup `python:3.14-slim` doesn't ship by
# default) — needed only inside the `vpn` sidecar
# (`app.services.vpn_control_server`, run as root there with
# CAP_NET_ADMIN/`/dev/net/tun`), not by `web`/`worker` themselves; same
# "harmless to have either way, reused from the same shared image"
# reasoning as the NetBird CLI above. Both ship in Debian's own repos,
# unlike NetBird — no extra apt source needed, and `apt-get update`
# immediately before `install` (rather than relying on a cached package
# index) is what actually gets the latest version Debian currently
# ships. Fetched fresh (latest Debian-packaged wireguard-tools) on every
# image build rather than pinned, unlike NetBird above — wireguard-tools
# carries no equivalent per-device persisted identity for a version bump
# to invalidate, so there's no matching risk to pin against, and a stale
# WireGuard userspace tool is still a real security/compatibility
# liability worth tracking automatically.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app && useradd --system --gid app --home-dir /app --create-home app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # uvicorn (web's CMD), celery (worker/beat's), and alembic (alembic.ini's
    # prepend_sys_path = .) both already make "app.*" importable relative
    # to the working directory on their own — a plain `python
    # scripts/create_admin.py` invocation (docker compose exec) doesn't
    # get that same treatment, so it needs /app on sys.path explicitly.
    PYTHONPATH=/app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app app ./app
COPY --chown=app:app alembic ./alembic
COPY --chown=app:app alembic.ini ./alembic.ini
# create_admin.py / reset_account.py are meant to be run inside the
# container (docker compose exec web python scripts/...), per
# wiki/Installation.md — generate_secrets.py and upgrade.sh are host-only
# tools but harmless to have here too, and copying the whole directory is
# simpler than picking files apart.
COPY --chown=app:app scripts ./scripts

RUN mkdir -p /app/data && chown app:app /app/data

# Which commit this image was built from — the `.git` directory itself is
# never copied in, so this is the only way `app.core.version` can know at
# runtime. Passed via `docker compose build --build-arg` (docker-compose.yml
# sets it from the GIT_COMMIT shell variable, which scripts/upgrade.sh
# exports before building); defaults to "unknown" for a plain `docker build`
# with nothing passed.
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
