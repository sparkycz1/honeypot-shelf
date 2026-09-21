"""Pydantic schemas for the user-management forms (`app/web/routes/users.py`)."""

from __future__ import annotations

import re
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.auth.security import USERNAME_PATTERN
from app.db.models.user import AccessLevel, AuthProvider

MIN_PASSWORD_LENGTH = 12

# Deliberately loose — a plausible-shape check, not full RFC 5322
# validation (no deliverability check either, since no confirmation email
# is ever sent). Shared by every place an address is entered by hand:
# `User.email` (app/web/routes/auth.py), a notification rule's own
# `target_email` (app/web/routes/notifications.py), and the admin-side
# Users edit form (app/web/routes/users.py).
#
# The domain side is a dot-separated run of labels, each of which
# excludes "." itself (`[^\s@.]+`) rather than the earlier, looser
# `[^\s@]+\.[^\s@]+` — that version let the local part's own `[^\s@]+`
# also match "." characters, so a long "@"-less input gave the regex
# engine many different ways to divide it between the two groups before
# failing: polynomial in the input length (CodeQL's py/polynomial-redos).
# Excluding "." from each label removes the ambiguity — every character
# now belongs to exactly one possible group — while still accepting
# every real address a plain `[^\s@]+@[^\s@]+\.[^\s@]+` did.
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$")


def looks_like_email(value: str) -> bool:
    return bool(_EMAIL_PATTERN.match(value))


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
    # This account's own email — see `User.email`'s own docstring
    # (Notifications' default destination address; not used for login).
    # Settable here so an admin can fill it in at creation time, same as
    # the user themselves can later from My account.
    email: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Required (and validated) only for AuthProvider.LOCAL — see
    # `_check_password_required`. LDAP/OIDC accounts have no Honeypot Shelf-side
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

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str | None) -> str | None:
        stripped = (value or "").strip()
        if not stripped:
            return None
        if not looks_like_email(stripped):
            raise ValueError("That doesn't look like a valid email address.")
        return stripped

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
    # See `UserCreate.email`'s own comment.
    email: str | None = Field(default=None, max_length=255)
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

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str | None) -> str | None:
        stripped = (value or "").strip()
        if not stripped:
            return None
        if not looks_like_email(stripped):
            raise ValueError("That doesn't look like a valid email address.")
        return stripped

    @field_validator("password")
    @classmethod
    def _validate_password_length(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value
