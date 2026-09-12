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

## RBAC: any number of companies, each with its own access level — no roles, no groups

Still deliberately much flatter than debcontrol's role/permission matrix,
but **not** single-company any more: a non-superadmin user holds zero or
more `CompanyMembership` rows (`app.db.models.company_membership`), each
naming one `Company` and one `AccessLevel` (`READ` or `READ_WRITE`) —
independent per company, so the same person can be `READ_WRITE` at one
company and `READ`-only at another. Zero memberships means logged-in but
scoped to nothing. There is still nothing in between `READ`/`READ_WRITE`,
no per-honeypot grants, and no custom roles to define. A `READ` membership
sees that company's honeypots/events/dashboard only; `READ_WRITE`
additionally manages that company's honeypots (register/rename/delete/
attach/detach) and acknowledges/annotates events — see
`app.auth.permissions`/`app.auth.scope` for the exact matrix.

**`is_superadmin`** is the one deliberate exception: a superadmin holds no
`CompanyMembership` row at all — it can see and manage every company,
every honeypot, and the Users/Companies admin pages. It exists because
Honeypot Shelf itself (the operator running honeypots for many customer
companies) needs a cross-tenant view; it is not part of the per-company
READ/READ_WRITE model and is granted by another superadmin only.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.api_token import ApiToken
    from app.db.models.company_membership import CompanyMembership
    from app.db.models.honeypot_notification_subscription import (
        HoneypotNotificationSubscription,
    )
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

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # Always stored lowercased (app.schemas.user normalizes it) — the login
    # identifier, the LDAP bind username, and (compared against a claim) the
    # OIDC identity, all at once. See the module docstring.
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # This account's own email — self-service (My account → Notifications),
    # or set by an admin from the Users edit form. Not used for login (see
    # `username` above); its only consumer today is Notifications, as the
    # default destination address — see `notification_target_email` below.
    # Not validated as deliverable (no confirmation email sent), only as a
    # plausible address shape (`app.schemas.user`).
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # A manually-entered notification destination, self-service only (an
    # admin does not set this for someone else) — e.g. a shared team alias
    # instead of this person's own inbox. Takes priority over `email` when
    # set; see `notification_target_email`.
    notification_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

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
    # One row per company this user has access to, each with its own
    # `access_level` — see `app.db.models.company_membership`. A
    # superadmin holds none; enforced in application code (the New/Edit
    # user forms), not a DB constraint — see the module docstring.
    memberships: Mapped[list[CompanyMembership]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    # --- TOTP (see app.auth.totp) — available for LOCAL and LDAP, not OIDC ---
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Brute-force lockout — shared by password checks and TOTP checks,
    # see app.auth.login. Reset to 0/None on any successful login step. ---
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(nullable=True)

    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # A superadmin's own personal SSH public key(s), self-service (My
    # account → SSH public keys) — one `authorized_keys`-ready line per
    # entry, newline-separated, never encrypted (these are public keys, not
    # secrets). Only ever read for a superadmin: Initialize
    # (`app.web.routes.initialize_ws`) pushes every superadmin's keys onto
    # a freshly provisioned device, and "Push to every honeypot" on the
    # account page (`app.tasks.jobs.push_superadmin_ssh_keys`) does the
    # same for the existing fleet — a company-scoped user can fill this in
    # too (nothing stops them), but nothing reads it for one, matching
    # `NEW_SSH_PORT`'s "superadmin-only, by design" reasoning: granting
    # host-level SSH into every honeypot fleet-wide is a superadmin-tier
    # capability, not something company scoping should ever widen.
    # `app.auth.ssh_keys.parse_ssh_public_keys` is what validates/parses
    # this at write time — never stored un-parsed.
    ssh_public_keys: Mapped[str | None] = mapped_column(Text, nullable=True)

    sessions: Mapped[list[UserSession]] = relationship(
        back_populates="user",
        foreign_keys="UserSession.user_id",
        cascade="all, delete-orphan",
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
    notification_subscriptions: Mapped[list[HoneypotNotificationSubscription]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def can_write(self) -> bool:
        """Superadmin, or `READ_WRITE` on **at least one** company — the
        generic "may this account write at all" signal used for nav-level
        gating (Initialize, Scheduling's own landing page — neither is
        scoped to one company). Per-company enforcement is a separate,
        narrower check — see `app.auth.scope.has_company_access`/
        `can_write_company` below, and `app.auth.permissions`."""
        return self.is_superadmin or any(
            m.access_level == AccessLevel.READ_WRITE for m in self.memberships
        )

    def company_ids(self) -> set[uuid.UUID]:
        """Every company this user holds any membership in (empty for a
        superadmin — see `app.auth.scope.visible_company_ids`, which is
        what call sites should use: it also knows to treat a superadmin's
        empty set as "no filter", not "no access")."""
        return {m.company_id for m in self.memberships}

    def can_write_company(self, company_id: uuid.UUID) -> bool:
        """Superadmin, or `READ_WRITE` membership in this exact company."""
        if self.is_superadmin:
            return True
        return any(
            m.company_id == company_id and m.access_level == AccessLevel.READ_WRITE
            for m in self.memberships
        )

    @property
    def notification_target_email(self) -> str | None:
        """Where a Notifications email for this user actually goes —
        `notification_email` (the manual override) if set, else `email`
        (this account's own), else `None` (nothing to send to yet). See
        `app.services.notifications`."""
        return self.notification_email or self.email

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
