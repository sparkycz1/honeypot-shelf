"""A single deployed OpenCanary honeypot (a Raspberry Pi at a customer
site), managed over SSH — same model debcontrol uses for a `Machine`,
merged with the honeypot-specific event-ingestion bookkeeping this
project added first.

Security notes (identical to debcontrol's `Machine`):
- `secret_encrypted` only holds a value for `AuthMethod.PASSWORD` (the
  discouraged fallback) — encrypted via `app.core.security.encrypt_secret`.
  For `AuthMethod.SSH_KEY` (the default/recommended method), the app
  connects using its own shared identity key (see
  `app.db.models.ssh_identity.SSHIdentity`), so there's nothing
  honeypot-specific to store.
- `host_key_fingerprint` is the SSH host key fingerprint this honeypot is
  "pinned" to. Until it's set, no connection will be established
  automatically (no silent "trust on first use") — the fingerprint must be
  explicitly confirmed by an operator outside this application and only
  then stored here.

Facts (`os_version`, `kernel_version`, `cpu_cores`, `ram_bytes`, `disks`,
`discovered_hostname`, `reboot_required`) are read over SSH — see
`app.ssh.facts` — once a host key fingerprint is pinned, and refreshed
periodically by the background worker. `is_reachable`/`last_ping_at` come
from a much cheaper, unauthenticated TCP-reachability check. Update
counts/packages mirror debcontrol's `Machine` exactly — see
`app.ssh.updates`/`app.ssh.packages`.

**Two independent "is this honeypot alive" signals coexist** — don't
conflate them: `is_reachable`/`last_ping_at` is the SSH-management-plane
check (same as debcontrol); `last_seen_at`/`last_seen_ip` is when this
honeypot last *produced* an OpenCanary event, found by Honeypot Shelf
itself SSH-polling OpenCanary's own log (see `app.ssh.canary_activity`,
`app.services.honeypot_status`) — a honeypot can be SSH-reachable but have
OpenCanary itself down, or vice versa.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.honeypot_company import honeypot_companies
from app.db.models.honeypot_tag import Tag, honeypot_tags
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.honeypot_event import HoneypotEvent


class AuthMethod(enum.StrEnum):
    SSH_KEY = "ssh_key"
    PASSWORD = "password"


class Honeypot(Base):
    __tablename__ = "honeypots"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    # Many-to-many, optionally empty (an unassigned honeypot — superadmin
    # visibility only). Replaces the old required single `company_id` FK —
    # see `app.db.models.honeypot_company`/`app.auth.scope`.
    companies: Mapped[list[Company]] = relationship(
        secondary=honeypot_companies, back_populates="honeypots", lazy="selectin"
    )

    # e.g. "acme-honey1" — the RPI name convention from the install
    # runbook (<firma>-honey<n>). Indexed: the list orders/searches by this.
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --- SSH management plane (see app.ssh.*, same shape as debcontrol's
    # Machine) ---
    ip_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(default=22, nullable=False)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_method: Mapped[AuthMethod | None] = mapped_column(
        pg_enum(AuthMethod, name="auth_method"), nullable=True
    )
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Free-form, cross-cutting labels independent of `companies` above.
    tags: Mapped[list[Tag]] = relationship(
        secondary=honeypot_tags, order_by="Tag.name", lazy="selectin"
    )

    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # A longer, Markdown-formatted runbook — rendered via
    # app.web.templating's `markdown` filter.
    runbook: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False, index=True)

    # --- Facts, discovered over SSH (see app.ssh.facts) ---
    discovered_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cpu_cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cpu_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ram_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    ram_speed_mhz: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # `/etc/os-release`'s `ID=` field — used only to pick an OS logo.
    os_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    reboot_required: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    uptime_seconds: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    process_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    filesystems: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    network_interfaces: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    facts_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Cheap per-minute reachability check (TCP connect to the SSH port) ---
    is_reachable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_ping_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # When this honeypot most recently *transitioned* from reachable (or
    # never-yet-checked) to unreachable — `None` while reachable. Distinct
    # from `last_ping_at`, which is overwritten on every sweep tick
    # regardless of outcome and so can't answer "how long has it actually
    # been down." Exists for Notifications' own debounce (`app.tasks.jobs.
    # _ping_all_honeypots`, `HoneypotNotificationSubscription.
    # unavailable_after_minutes`) — cleared back to `None` the moment a
    # sweep finds it reachable again.
    unreachable_since: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Per-honeypot overrides of the global `.env` sweep cadences —
    # NULL means "use the global default". See app.tasks.jobs._due_honeypots.
    reachability_check_interval_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    facts_refresh_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    monitoring_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    monitoring_history_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    opencanary_log_poll_interval_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # --- Monitoring tab: CPU/RAM/disk-usage samples and the systemd service
    # snapshot ---
    monitoring_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    services_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Post-onboarding readiness check (see app.ssh.readiness) ---
    readiness_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    readiness_missing: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # --- Update availability: apt, flatpak, snap ---
    upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    security_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flatpak_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snap_upgradable_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    updates_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    apt_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )
    flatpak_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )
    snap_upgradable_packages: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON, nullable=True
    )
    packages_updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # --- Event ingestion (this project's own addition — see
    # app.services.honeypot_status) ---
    last_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)

    # --- Activity tab: SSH-polling OpenCanary's own log (see
    # app.ssh.canary_activity, app.tasks.jobs.poll_all_honeypot_canary_logs)
    # — the only way a HoneypotEvent row gets created; see
    # HoneypotEvent.source. ---
    # Byte offset already read from OPENCANARY_LOG_PATH — only the bytes
    # appended since this offset are fetched on the next poll. Reset to 0 if
    # the file has shrunk since (rotated/truncated).
    opencanary_log_offset: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    opencanary_log_polled_at: Mapped[datetime | None] = mapped_column(nullable=True)

    events: Mapped[list[HoneypotEvent]] = relationship(
        back_populates="honeypot", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Honeypot(id={self.id!r}, name={self.name!r})"
