# syntax=docker/dockerfile:1

# --- Stage 1: build the virtualenv with uv -----------------------------------
FROM python:3.14.7-slim AS builder

# Official static uv binary — no need to pip-install it into the image.
# Pinned to an exact version (same reasoning as Postgres/Redis/Caddy) —
# `:latest` would silently pick up a new uv release, and thus a possibly
# different dependency resolver/behavior, on every rebuild.
COPY --from=ghcr.io/astral-sh/uv:0.12.12 /uv /uvx /usr/local/bin/

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
FROM python:3.14.7-slim AS runtime

# The netbird CLI/daemon binary only — installed straight from its GitHub
# release tarball, not the `.deb` (whose postinst script tries to install
# and start a SysV init service — nothing this image ever has, since it
# only ever runs a single foreground process, so that install would fail
# the build for no benefit; nothing here needs the systemd unit the `.deb`
# would set up either). Never run inside `web`/`worker` themselves (that
# needs CAP_NET_ADMIN/`/dev/net/tun`, which this image's containers
# deliberately don't have; see app/services/netbird.py's module docstring)
# — this lets `web` issue `netbird up/down/status` against the optional
# `docker-compose.vpn.yml` sidecar's daemon over a shared socket volume
# instead. Harmless to have installed even when that overlay isn't used —
# the CLI just fails with a clear "can't reach the daemon" error, same as
# any other optional integration (LDAP/OIDC/syslog) left unconfigured.
ARG NETBIRD_VERSION=0.78.1
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL \
        "https://github.com/netbirdio/netbird/releases/download/v${NETBIRD_VERSION}/netbird_${NETBIRD_VERSION}_linux_amd64.tar.gz" \
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
# unlike NetBird — no extra apt source needed.
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
