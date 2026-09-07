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

    # --- Honeypot ingest ---
    # Bearer token an OpenCanary host must present when pushing events to
    # POST /api/ingest/events (syslog/HTTP forwarder on the Pi — see
    # wiki/Honeypot-Onboarding.md). Rotate per-honeypot tokens live under
    # Honeypot.ingest_token_hash instead once that's needed; this shared
    # token is the bootstrap/fallback path, mirroring debcontrol's
    # INFORM_TOKEN.
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

    @field_validator("secret_key", "encryption_key", "ingest_token")
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


@lru_cache
def get_settings() -> Settings:
    """Settings are loaded once and cached — validation happens on first import."""
    return Settings()  # values come from the environment / .env (pydantic-settings)
