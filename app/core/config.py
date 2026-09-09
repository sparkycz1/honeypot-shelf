"""Application configuration.

All settings are read from the environment (12-factor app) via
pydantic-settings. Nothing sensitive should ever be hardcoded here or
committed — see `.env.example`.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = Field(default="development", alias="APP_ENV")
    secret_key: SecretStr = Field(alias="SECRET_KEY")
    encryption_key: SecretStr = Field(alias="ENCRYPTION_KEY")

    # --- PostgreSQL ---
    # `database_url` is built from these parts if not set explicitly, so the
    # password only has to be written once. Set `database_url` directly
    # instead if you need something these parts can't express.
    postgres_user: str = Field(default="honeyhive", alias="POSTGRES_USER")
    postgres_password: SecretStr = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="honeyhive", alias="POSTGRES_DB")
    # Defaults match the docker-compose service name — override for a local,
    # non-Docker Postgres (e.g. "localhost").
    postgres_host: str = Field(default="db", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL")

    # SQLAlchemy async engine pool sizing for the **web** process only — see
    # app/db/session.py. (The Celery worker's own per-child engine uses
    # NullPool instead — see app/tasks/celery_app.py's `_init_worker_process`.)
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")

    # --- Redis (Celery broker + result backend, and the login rate limiter) ---
    redis_password: SecretStr = Field(alias="REDIS_PASSWORD")
    redis_host: str = Field(default="redis", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_url_override: str | None = Field(default=None, alias="REDIS_URL")

    # --- SSH management plane (app/ssh/*, app/tasks/jobs.py) — ported from
    # debcontrol close to unchanged, since a honeypot is managed exactly
    # like a debcontrol Machine (terminal, facts, packages, updates,
    # power). See wiki/Architecture.md. ---
    ssh_connect_timeout: int = Field(default=10, alias="SSH_CONNECT_TIMEOUT")

    # How often (seconds) Celery Beat schedules a refresh of OS/kernel/CPU/
    # RAM/disk facts (and installed packages, and update availability) for
    # every honeypot with a pinned host key.
    facts_refresh_interval_seconds: int = Field(
        default=600, alias="FACTS_REFRESH_INTERVAL_SECONDS"
    )

    # How often (seconds) the "is it alive" status badge's reachability
    # sweep (a plain TCP connect to the SSH port, no authentication) runs
    # for every honeypot. Deliberately its own, much shorter, default than
    # `facts_refresh_interval_seconds`.
    reachability_check_interval_seconds: int = Field(
        default=60, alias="REACHABILITY_CHECK_INTERVAL_SECONDS"
    )

    # How many honeypots the reachability sweep checks concurrently — a
    # semaphore, not a thread/process count.
    reachability_check_concurrency: int = Field(
        default=20, alias="REACHABILITY_CHECK_CONCURRENCY"
    )

    # How often (seconds) the Monitoring tab's CPU/RAM/disk-usage sample
    # (and the cheap "how many systemd services are failed" count) is
    # taken for every honeypot — a real SSH round trip (unlike the plain
    # TCP reachability check above), but much lighter than a full facts
    # refresh.
    monitoring_interval_seconds: int = Field(default=120, alias="MONITORING_INTERVAL_SECONDS")

    # apt update/upgrade/autoremove/autoclean can legitimately take a long
    # time — this is the max wall-clock time given to that whole sequence,
    # distinct from `ssh_connect_timeout` (which only bounds establishing
    # the connection itself).
    update_timeout_seconds: int = Field(default=1800, alias="UPDATE_TIMEOUT_SECONDS")

    # --- NetBird for HoneyHive itself (app.services.netbird, Settings ->
    # NetBird) — lets `web`/`worker` reach a honeypot that's only addressable
    # over NetBird (e.g. behind a NAT with no forwarded SSH port), by sharing
    # the `netbird` sidecar container's network namespace (see
    # docker-compose.vpn.yml). These three are deploy-time paths, not
    # something an operator tunes — hence env config, not a Settings-page
    # field, unlike the setup key/management URL/enabled flag below, which
    # *are* on the Settings page (`AppSettings.netbird_*`). ---
    # Where the `netbird` CLI (installed in this image, see Dockerfile)
    # reaches the sidecar's daemon — must match that container's own
    # `--daemon-addr`/default, over the shared `netbird_sock` volume.
    netbird_daemon_addr: str = Field(
        default="unix:///var/run/netbird/sock", alias="NETBIRD_DAEMON_ADDR"
    )
    # The sidecar's log file, over the shared `netbird_log` volume — read
    # (never written) by the Settings -> NetBird log viewer.
    netbird_log_path: str = Field(
        default="/var/log/netbird/client.log", alias="NETBIRD_LOG_PATH"
    )
    netbird_command_timeout_seconds: int = Field(
        default=30, alias="NETBIRD_COMMAND_TIMEOUT_SECONDS"
    )

    # --- WireGuard for HoneyHive itself (app.services.wireguard, Settings
    # -> VPN) — the other, mutually-exclusive VPN provider (see
    # `AppSettings.VpnProvider`). Unlike NetBird, plain `wireguard-tools`
    # has no daemon+CLI split of its own, so `app.services.vpn_control_server`
    # (run inside the `vpn` sidecar, see docker-compose.vpn.yml) is a small
    # purpose-built stand-in for one — this is where `web` reaches it.
    vpn_control_addr: str = Field(
        default="/var/run/vpn/control.sock", alias="VPN_CONTROL_ADDR"
    )
    vpn_command_timeout_seconds: int = Field(
        default=30, alias="VPN_COMMAND_TIMEOUT_SECONDS"
    )
    # `vpn_control_server`'s own log (connect/disconnect attempts, results,
    # errors) — over a shared volume between the sidecar and `web`, the
    # same idea as `netbird_log_path` above. Plain `wireguard-tools` keeps
    # no log of its own (`wg-quick`/`wg` are one-shot commands, nothing
    # daemonized to log continuously) — this is the closest equivalent,
    # written by the control server itself rather than by WireGuard.
    wireguard_log_path: str = Field(
        default="/var/log/vpn/control.log", alias="WIREGUARD_LOG_PATH"
    )

    # Comma-separated absolute path prefixes the Logs tab's "view an
    # arbitrary file" feature is allowed to read from a managed honeypot
    # (app.ssh.logs.is_path_allowed) — a UX/scope guardrail, not a hard
    # security boundary against an account that already has write access
    # (who could read the same file directly in the terminal anyway).
    log_file_allowed_paths: str = Field(
        default="/var/log,/var/lib/docker/containers,/mnt/tmpfs", alias="LOG_FILE_ALLOWED_PATHS"
    )

    # Bearer token a not-yet-registered honeypot presents when announcing
    # itself via POST /api/inform (see app/db/models/pending_honeypot.py) —
    # distinct from INGEST_TOKEN below, which is for an *already-registered*
    # honeypot's OpenCanary event stream.
    inform_token: SecretStr = Field(alias="INFORM_TOKEN")

    # --- Honeypot event ingestion (this project's own addition — see
    # app/web/routes/ingest.py) ---
    # Bearer token an OpenCanary host's forwarder must present when pushing
    # events to POST /api/ingest/{id}/events (see
    # wiki/Honeypot-Onboarding.md). Rotate a per-honeypot token
    # (Honeypot.ingest_token_hash) instead once a specific honeypot needs
    # revoking individually; this shared token is the bootstrap/fallback
    # path, mirroring debcontrol's INFORM_TOKEN shape.
    ingest_token: SecretStr = Field(alias="INGEST_TOKEN")

    # How long (days) raw honeypot events are kept before the daily
    # housekeeping job purges them. Daily/company summary rollups are kept
    # indefinitely (see wiki/Architecture.md).
    event_retention_days: int = Field(default=180, alias="EVENT_RETENTION_DAYS")

    # A honeypot with no ingested event for this many seconds is shown as
    # "offline" on the dashboard/honeypot list.
    honeypot_offline_after_seconds: int = Field(
        default=600, alias="HONEYPOT_OFFLINE_AFTER_SECONDS"
    )

    # How often (seconds) HoneyHive itself connects over SSH and reads
    # whatever's new in OpenCanary's own log (`app.ssh.logs.HONEYPOT_LOG_PATH`)
    # since the last read, for every honeypot with a pinned host key — the
    # Honeypot Activity tab (`app.ssh.canary_activity`,
    # `app.tasks.jobs.poll_all_honeypot_canary_logs`). Each new line found
    # this way is recorded exactly like a pushed event (see
    # `app.services.honeypot_events`) — `HoneypotEvent.source` distinguishes
    # the two — so a honeypot never needs its own forwarder set up (see
    # wiki/Honeypot-Onboarding.md) just to show up on this tab or the
    # Dashboard. Overridable per honeypot
    # (`Honeypot.opencanary_log_poll_interval_seconds`); `None` there means
    # "use this default". Same SSH round trip shape as `monitoring_interval_
    # seconds` above, just aimed at OpenCanary's log instead of `/proc`.
    opencanary_log_poll_interval_seconds: int = Field(
        default=120, alias="OPENCANARY_LOG_POLL_INTERVAL_SECONDS"
    )

    # --- Branding (nav-bar/login logo, favicon) ---
    # Either an absolute/relative URL (http://, https://) or a filesystem
    # path readable inside the `web` container. A URL is linked directly;
    # a filesystem path is served by the app itself at `/branding/logo` (see
    # app/web/routes/branding.py) — mount it into the container first (see
    # docker-compose.yml's commented-out `branding` volume). Unset means
    # "use the built-in bee mark". See wiki/Installation.md#custom-logo--favicon.
    logo_source: str | None = Field(default=None, alias="LOGO_SOURCE")
    # Same idea as `logo_source`, for the browser-tab favicon. Unset means
    # "use the built-in bee mark".
    favicon_source: str | None = Field(default=None, alias="FAVICON_SOURCE")

    # Which reverse proxies to trust `X-Forwarded-Proto` from, for deriving
    # the *scheme* (http/https, ws/wss) a request actually arrived as —
    # nothing else (host/port already come through correctly from a
    # forwarded Host header, which every reverse proxy passes through
    # untouched by default). Without this, a TLS-terminating proxy leaves
    # the app seeing plain "http" for every request no matter what the
    # browser actually used, which breaks WebAuthn/passkeys (the verified
    # origin has to match exactly what the browser sent) and OIDC login
    # (the redirect_uri built from the request would have the wrong
    # scheme). Comma-separated IPs/CIDRs, or the default "*" to trust any
    # peer — safe here even from an untrusted direct client, since the
    # only things derived from the corrected scheme are values a forged
    # header can only cause to *mismatch* a cryptographic check elsewhere
    # (WebAuthn's browser-signed origin, an OIDC provider's own registered
    # redirect_uri) and fail closed, never one it can forge a match for.
    # Narrow this to your actual proxy's IP/subnet if you'd rather not rely
    # on that reasoning. See app.core.proxy_headers.
    trusted_proxy_ips: str = Field(default="*", alias="TRUSTED_PROXY_IPS")

    @property
    def trust_all_proxies(self) -> bool:
        return self.trusted_proxy_ips.strip() == "*"

    @property
    def trusted_proxy_networks(
        self,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parsed `trusted_proxy_ips` as `ipaddress` networks — empty when
        `trust_all_proxies` is True (that case is checked separately, since
        "*" isn't a valid network literal). A bare IP (no `/prefix`) is
        accepted via `ip_network(..., strict=False)`, same as a /32 or /128."""
        if self.trust_all_proxies:
            return []
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for part in self.trusted_proxy_ips.split(","):
            part = part.strip()
            if not part:
                continue
            networks.append(ipaddress.ip_network(part, strict=False))
        return networks

    # Whether to also trust `X-Forwarded-For` from a `trusted_proxy_ips`
    # peer, to correct `request.client.host` (the audit log's `ip_address`
    # column, and the login/TOTP rate limiter's per-source bucket key —
    # app/auth/rate_limit.py) to the real client behind a reverse proxy
    # instead of the proxy's own address. Off by default, unlike scheme
    # trust above: this one *is* a real risk to default on — a client that
    # can set an arbitrary X-Forwarded-For on each request (true of anyone
    # reaching this app directly, bypassing your real proxy, e.g. if this
    # app's port is also exposed) could make every login/TOTP attempt look
    # like a different source and defeat the rate limiter entirely if this
    # were trusted from just anyone. Turn this on only once you've also
    # narrowed `TRUSTED_PROXY_IPS` above to your actual proxy's own
    # address/subnet (not the default "*") — see app.core.proxy_headers.
    trust_forwarded_for: bool = Field(default=False, alias="TRUST_FORWARDED_FOR")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # IANA timezone name (e.g. "Europe/Prague") the UI renders timestamps
    # in. Falls back to UTC if unset or not a recognized zone. Data is
    # always stored in Postgres as UTC regardless of this — only display
    # formatting is affected. The same variable also sets every container's
    # own OS timezone (see docker-compose.yml).
    tz: str = Field(default="UTC", alias="TZ")

    @field_validator("secret_key", "encryption_key", "ingest_token", "inform_token")
    @classmethod
    def _reject_placeholder_secrets(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.startswith("change-me") or len(raw) < 16:
            raise ValueError(
                "Placeholder or too-short secret in configuration. "
                "Generate a real value (see .env.example) before starting the app."
            )
        return value

    @property
    def database_url(self) -> str:
        """`DATABASE_URL` if set directly, otherwise built from the
        `postgres_*` parts so the password is only written once in `.env`.
        The password is percent-encoded (`quote`, `safe=""`) since a raw
        `@`, `/`, or `:` in it would otherwise be parsed as URL structure,
        not part of the credential."""
        if self.database_url_override is not None:
            return self.database_url_override
        password = quote(self.postgres_password.get_secret_value(), safe="")
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Same pattern as `database_url` above, built from the `redis_*` parts."""
        if self.redis_url_override is not None:
            return self.redis_url_override
        password = quote(self.redis_password.get_secret_value(), safe="")
        return f"redis://:{password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def log_file_allowed_path_list(self) -> list[str]:
        """`log_file_allowed_paths` split and cleaned up — empty entries
        (e.g. a trailing comma) dropped, no trailing slash (so a prefix
        check via `str.startswith` doesn't require the caller to normalize
        first)."""
        return [
            part.strip().rstrip("/")
            for part in self.log_file_allowed_paths.split(",")
            if part.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Settings are loaded once and cached — validation happens on first import."""
    return Settings()  # values come from the environment / .env (pydantic-settings)
