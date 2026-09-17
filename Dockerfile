# syntax=docker/dockerfile:1

# --- Stage 1: build the virtualenv with uv -----------------------------------
FROM python:3.14.7-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6 AS builder

# Official static uv binary — no need to pip-install it into the image.
# Pinned to an exact version (same reasoning as Postgres/Redis/Caddy) —
# `:latest` would silently pick up a new uv release, and thus a possibly
# different dependency resolver/behavior, on every rebuild.
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /uvx /usr/local/bin/

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

# Both VPN clients below are fetched fresh (latest NetBird release,
# latest Debian-packaged wireguard-tools) on every image build rather
# than pinned to a version this Dockerfile hardcodes — a stale VPN client
# is a real security/compatibility liability (NetBird's management
# protocol and WireGuard's kernel module both move), and unlike the
# app's own Python dependencies (deliberately pinned in uv.lock, bumped
# deliberately via Dependabot) there's no equivalent lockfile/PR-review
# story for either of these, so "always latest at build time" is the
# simpler, safer default here.
#
# CACHE_BUST alone (an ARG whose *value* changes) is what actually forces
# Docker to re-run both RUN layers below instead of reusing a
# months-old cached one — `docker compose build` on an unchanged
# Dockerfile would otherwise happily keep serving whatever NetBird/
# wireguard-tools version was cached from the very first build forever.
# `docker-compose.yml` sets this from a `CACHE_BUST` shell variable;
# `scripts/upgrade.sh` exports a fresh one (the current date) before
# every build, same mechanism as `GIT_COMMIT` below. Defaults to
# "unknown" for a plain `docker build` with nothing passed — cache reuse
# in that case is the same tradeoff a bare `docker build` already makes
# for every other layer.
ARG CACHE_BUST=unknown

# The netbird CLI/daemon binary only — installed straight from its latest
# GitHub release tarball, not the `.deb` (whose postinst script tries to
# install and start a SysV init service — nothing this image ever has,
# since it only ever runs a single foreground process, so that install
# would fail the build for no benefit; nothing here needs the systemd
# unit the `.deb` would set up either). Never run inside `web`/`worker`
# themselves (that needs CAP_NET_ADMIN/`/dev/net/tun`, which this image's
# containers deliberately don't have; see app/services/netbird.py's
# module docstring) — this lets `web` issue `netbird up/down/status`
# against the optional `docker-compose.vpn.yml` sidecar's daemon over a
# shared socket volume instead. Harmless to have installed even when
# that overlay isn't used — the CLI just fails with a clear "can't reach
# the daemon" error, same as any other optional integration (LDAP/OIDC/
# syslog) left unconfigured.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && netbird_latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/netbirdio/netbird/releases/latest)" \
    && netbird_version="${netbird_latest_url##*/v}" \
    && curl -fsSL \
        "https://github.com/netbirdio/netbird/releases/download/v${netbird_version}/netbird_${netbird_version}_linux_amd64.tar.gz" \
        | tar xz -C /usr/local/bin netbird \
    && chmod +x /usr/local/bin/netbird \
    && rm -rf /var/lib/apt/lists/*

# `wg`/`wg-quick` (plus `iproute2`'s `ip` command, which `wg-quick` shells
# out to for the interface/route setup `python:3.14-slim` doesn't ship by
# default) — needed only inside the `vpn` sidecar
# (`app.services.vpn_control_server`, run as root there with
# CAP_NET_ADMIN/`/dev/net/tun`), not by `web`/`worker` themselves; same
# "harmless to have either way, reused from the same shared image"
# reasoning as the NetBird CLI above. Both ship in Debian's own repos,
# unlike NetBird — no extra apt source needed, and `apt-get update`
# immediately before `install` (rather than relying on a cached package
# index) is what actually gets the latest version Debian currently ships.
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
