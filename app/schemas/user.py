"""Pydantic schemas for the user-management forms (`app/web/routes/users.py`)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.auth.security import USERNAME_PATTERN
from app.db.models.user import AccessLevel, AuthProvider

MIN_PASSWORD_LENGTH = 12


class MembershipInput(BaseModel):
    """One row of the New/Edit user form's repeated "company + access
    level" fieldset — see `app.db.models.company_membership`."""

    company_id: uuid.UUID
    access_level: AccessLevel


class _CompanyScopeMixin(BaseModel):
    # --- RBAC (see app.db.models.user's module docstring) ---
    # Exactly one of these two shapes: `is_superadmin=True` with `memberships`
    # empty, or `is_superadmin=False` with at least one membership and no
    # company repeated — a user can hold only one access level per company.
    is_superadmin: bool = False
    memberships: list[MembershipInput] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_company_scope(self) -> _CompanyScopeMixin:
        if self.is_superadmin:
            if self.memberships:
                raise ValueError("A superadmin has no company memberships.")
        elif not self.memberships:
            raise ValueError("A non-superadmin user needs at least one company membership.")
        company_ids = [m.company_id for m in self.memberships]
        if len(company_ids) != len(set(company_ids)):
            raise ValueError("Each company can only be granted one access level.")
        return self


class UserCreate(_CompanyScopeMixin):
    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Required (and validated) only for AuthProvider.LOCAL — see
    # `_check_password_required`. LDAP/OIDC accounts have no HoneyHive-side
    # password at all.
    password: str | None = Field(default=None, max_length=255)
    api_access_enabled: bool = False

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise ValueError(
                "Username must be 3-64 characters: lowercase letters, digits, '.', '_', or '-', "
                "starting with a letter or digit."
            )
        return normalized

    @field_validator("password")
    @classmethod
    def _validate_password_length(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value

    @model_validator(mode="after")
    def _check_password_required(self) -> UserCreate:
        if self.auth_provider == AuthProvider.LOCAL:
            if not self.password:
                raise ValueError("A local account needs a password.")
        elif self.password:
            raise ValueError(f'"{self.auth_provider.value}" accounts don\'t set a password here.')
        return self


class UserUpdate(_CompanyScopeMixin):
    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Blank = keep the existing password unchanged (only meaningful when
    # `auth_provider` is already, or is becoming, LOCAL).
    password: str | None = Field(default=None, max_length=255)
    api_access_enabled: bool = False
    is_active: bool = True

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise ValueError(
                "Username must be 3-64 characters: lowercase letters, digits, '.', '_', or '-', "
                "starting with a letter or digit."
            )
        return normalized

    @field_validator("password")
    @classmethod
    def _validate_password_length(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value
