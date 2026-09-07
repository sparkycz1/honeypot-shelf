"""HoneyHive user accounts.

Every account is created inside HoneyHive first — there's no auto-provisioning
from LDAP or OIDC (see `app.auth.login`, `app.auth.oidc`). `auth_provider`
just decides *how* that account proves who it is:

- `LOCAL`: a password stored here (`password_hash`, argon2id — see
  `app.auth.security`).
- `LDAP`: binds against the directory configured in Settings, using this
  account's `username` as the LDAP username — no separate field for that
  (see `app.auth.ldap`).
- `OIDC`: redirected to the configured provider; the account is matched by
  comparing `username` against a claim from the ID token (which claim is
  configurable in Settings — `app.db.models.app_settings.AppSettings.oidc_username_claim`).

`LOCAL` and `LDAP` accounts can additionally enroll TOTP (`app.auth.totp`);
`OIDC` accounts can't — the provider's own MFA (if any) is what backs that
login instead.

## RBAC: one company, one access level — no roles, no groups

This is deliberately much flatter than debcontrol's role/permission matrix,
per the product decision behind HoneyHive: **every non-superadmin user
belongs to exactly one `Company`** (`company_id`, required) and holds
exactly one `AccessLevel` on it — `READ` or `READ_WRITE`. There is nothing
in between, no per-honeypot grants, and no custom roles to define. A
`READ` user sees that company's honeypots/events/dashboard only; a
`READ_WRITE` user can additionally manage that company's honeypots
(register/rename/delete) and acknowledge/annotate events — see
`app.auth.permissions` for the exact matrix.

**`is_superadmin`** is the one deliberate exception: a superadmin has no
`company_id` and no `access_level` of its own — it can see and manage
every company, every honeypot, and the Users/Companies admin pages. It
exists because HoneyHive itself (the operator running honeypots for many
customer companies) needs a cross-tenant view; it is not part of the
per-company READ/READ_WRITE model and is granted by another superadmin
only.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.api_token import ApiToken
    from app.db.models.company import Company
    from app.db.models.totp_recovery_code import TotpRecoveryCode
    from app.db.models.user_session import UserSession
    from app.db.models.webauthn_credential import WebAuthnCredential


class AuthProvider(enum.StrEnum):
    LOCAL = "local"
    LDAP = "ldap"
    OIDC = "oidc"


class AccessLevel(enum.StrEnum):
    """What a non-superadmin user may do within their own `Company` — see
    the module docstring. `READ_WRITE` always implies everything `READ`
    grants; there is no third tier."""

    READ = "read"
    READ_WRITE = "read_write"


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # Either a superadmin (no company/access_level) or a regular,
        # company-scoped user (both set) — never a half-configured row.
        # Enforced here, not just in application code, so a bug in a form
        # handler can't silently create a user with a company but no access
        # level (locked out of everything) or an access level but no
        # company (scoped to nothing).
        CheckConstraint(
            "(is_superadmin AND company_id IS NULL AND access_level IS NULL) "
            "OR (NOT is_superadmin AND company_id IS NOT NULL AND access_level IS NOT NULL)",
            name="superadmin_xor_company_scope",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # Always stored lowercased (app.schemas.user normalizes it) — the login
    # identifier, the LDAP bind username, and (compared against a claim) the
    # OIDC identity, all at once. See the module docstring.
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # This account's own UI language, self-service (My account → Language) —
    # a locale *code* (e.g. "en", "cs"). `None` means "use the default"
    # (English). See app/i18n/__init__.py.
    locale: Mapped[str | None] = mapped_column(String(16), nullable=True)

    auth_provider: Mapped[AuthProvider] = mapped_column(
        pg_enum(AuthProvider, name="auth_provider"), nullable=False
    )
    # Only ever set for AuthProvider.LOCAL.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Set when an admin assigns a new password (creation, or a reset) — the
    # user is forced to pick their own before doing anything else. Never set
    # for LDAP/OIDC accounts (there's no HoneyHive-side password to change).
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # A disabled account can't log in and gets no new sessions, but is kept
    # (not deleted) so its username stays out of the audit trail's history
    # without orphaning past entries.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Whether this user is allowed to create/use API tokens at all — see
    # `app.auth.api_tokens`. Checked both at token-creation time and live on
    # every API request, so unchecking it cuts off existing tokens
    # immediately.
    api_access_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- RBAC: company + access level (see module docstring). Both NULL for
    # a superadmin, both required otherwise — enforced by the CheckConstraint
    # above. ---
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("companies.id", ondelete="RESTRICT"), nullable=True
    )
    access_level: Mapped[AccessLevel | None] = mapped_column(
        pg_enum(AccessLevel, name="access_level"), nullable=True
    )
    company: Mapped[Company | None] = relationship(back_populates="users", lazy="joined")

    # --- TOTP (see app.auth.totp) — available for LOCAL and LDAP, not OIDC ---
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Brute-force lockout — shared by password checks and TOTP checks,
    # see app.auth.login. Reset to 0/None on any successful login step. ---
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    totp_recovery_codes: Mapped[list[TotpRecoveryCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    webauthn_credentials: Mapped[list[WebAuthnCredential]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def can_write(self) -> bool:
        """Superadmin or `READ_WRITE` on their own company — see
        `app.auth.permissions` for how this is used alongside company
        scoping (a non-superadmin can only ever write within
        `self.company_id`)."""
        return self.is_superadmin or self.access_level == AccessLevel.READ_WRITE

    @property
    def is_locked_out(self) -> bool:
        if self.locked_until is None:
            return False
        now = datetime.now(UTC)
        if self.locked_until.tzinfo is not None:
            return self.locked_until > now
        # Naive value (e.g. read back from SQLite in tests, which drops
        # tzinfo on round-trip) — this app always writes `locked_until` as
        # UTC, so a naive value here is treated as already being UTC rather
        # than local time.
        return self.locked_until > now.replace(tzinfo=None)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"User(id={self.id!r}, username={self.username!r})"
