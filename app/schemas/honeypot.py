"""Pydantic schemas for honeypot forms.

`secret` is only ever an input here — nothing in this module represents an
outbound/read shape, so there's no risk of it accidentally round-tripping
into a response.
"""

from __future__ import annotations

import ipaddress
import uuid

from pydantic import BaseModel, Field, field_validator

from app.db.models.honeypot import AuthMethod
from app.services.honeypot_tags import normalize_tag_names


def _check_ip_address(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f'"{value}" is not a valid IP address.') from exc
    return value


class HoneypotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    secret: str | None = Field(
        default=None, description="Password — only used when auth_method is 'password'."
    )
    # Any number of companies, including none (superadmin-only visibility
    # until one is attached) — see app.db.models.company's module
    # docstring. See app/web/routes/honeypots.py's create route for how
    # this is resolved for a company-scoped account (only companies that
    # account can write are ever offered/accepted).
    company_ids: list[uuid.UUID] = Field(default_factory=list)
    location: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    # Free-form, independent of company_id — see app.db.models.honeypot_tag.
    tags: list[str] = Field(default_factory=list)
    # Longer Markdown-formatted notes — see Honeypot.runbook's own docstring
    # for how this differs from `description` above.
    runbook: str | None = Field(default=None, max_length=20_000)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, value: str) -> str:
        return _check_ip_address(value)

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)


class HoneypotUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    secret: str | None = Field(
        default=None,
        description="Password — leave empty to keep the current one unchanged.",
    )
    company_ids: list[uuid.UUID] = Field(default_factory=list)
    location: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    tags: list[str] = Field(default_factory=list)
    runbook: str | None = Field(default=None, max_length=20_000)
    is_active: bool = True
    # Per-honeypot overrides of the global `.env` sweep cadences — `None`
    # means "use the global default" (see `Honeypot.
    # reachability_check_interval_seconds`/`facts_refresh_interval_seconds`).
    reachability_check_interval_seconds: int | None = Field(default=None, ge=1)
    facts_refresh_interval_seconds: int | None = Field(default=None, ge=1)
    monitoring_interval_seconds: int | None = Field(default=None, ge=1)
    monitoring_history_retention_days: int | None = Field(default=None, ge=1)
    opencanary_log_poll_interval_seconds: int | None = Field(default=None, ge=1)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, value: str) -> str:
        return _check_ip_address(value)

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)
