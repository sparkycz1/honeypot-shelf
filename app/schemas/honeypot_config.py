"""Pydantic schemas for exporting/importing honeypot & company *configuration*
— deliberately not a credentials backup. See
`app.services.honeypot_config`'s module docstring for the full design
rationale (what's excluded and why, and the conflict-handling policy).
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.db.models.honeypot import AuthMethod
from app.services.honeypot_tags import normalize_tag_names


class HoneypotExport(BaseModel):
    """One honeypot's structural configuration — no `secret_encrypted`
    (password/key material) and no `host_key_fingerprint`, ever. See
    `app.services.honeypot_config` for why."""

    name: str = Field(min_length=1, max_length=255)
    ip_address: str | None = Field(default=None, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    auth_method: AuthMethod | None = None
    # Any number of companies, including none — a honeypot no longer
    # requires exactly one (see app.db.models.company's module docstring).
    companies: list[str] = Field(default_factory=list)
    location: str | None = None
    description: str | None = None
    runbook: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_active: bool = True

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)


class CompanyExport(BaseModel):
    """One company's configuration. `members` is informational only on
    export (a convenience for a human reading the JSON) — on import,
    membership is always driven by each honeypot's own `company` field, not
    by this list, so the two can never disagree about who belongs where."""

    name: str = Field(min_length=1, max_length=255)
    notes: str | None = None
    members: list[str] = Field(default_factory=list)


class HoneypotConfigExport(BaseModel):
    """The full export/import payload shape — every honeypot and company a
    given user can see."""

    honeypots: list[HoneypotExport] = Field(default_factory=list)
    companies: list[CompanyExport] = Field(default_factory=list)
