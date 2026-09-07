"""Pydantic schemas for company forms."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

# "All honeypots" is a built-in, automatic virtual company (see
# app/web/routes/companies.py) — reserved so a real, manually-managed
# company can't be created with the same name and confuse the two.
RESERVED_COMPANY_NAMES = {"all"}


class CompanyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def _reject_reserved_name(cls, value: str) -> str:
        if value.strip().lower() in RESERVED_COMPANY_NAMES:
            raise ValueError(
                f'"{value}" is a reserved name (the built-in "All honeypots" view) '
                "— pick a different name."
            )
        return value
