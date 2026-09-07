"""Application configuration.

All settings are read from the environment (12-factor app) via
pydantic-settings. Nothing sensitive should ever be hardcoded here or
committed — see `.env.example`.
"""

from __future__ import annotations

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

    # Comma-separated absolute path prefixes the Logs tab's "view an
    # arbitrary file" feature is allowed to read from a managed honeypot
    # (app.ssh.logs.is_path_allowed) — a UX/scope guardrail, not a hard
    # security boundary against an account that already has write access
    # (who could read the same file directly in the terminal anyway).
    log_file_allowed_paths: str = Field(
        default="/var/log,/var/lib/docker/containers", alias="LOG_FILE_ALLOWED_PATHS"
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
