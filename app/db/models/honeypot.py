"""A deployed OpenCanary instance (a Raspberry Pi at a customer site).

HoneyHive doesn't SSH into honeypots or manage them remotely (unlike
debcontrol's `Machine`) — see `app.db.models.honeypot_event` and
`wiki/Architecture.md` for the actual data flow: a honeypot pushes its own
events to HoneyHive; HoneyHive never reaches back into it. This row is
therefore mostly identity + last-seen bookkeeping, not a live-managed
resource.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.honeypot_event import HoneypotEvent


class HoneypotStatus(enum.StrEnum):
    """Derived, not stored as the source of truth — `Honeypot.status`
    (a property, see below) compares `last_seen_at` against
    `Settings.honeypot_offline_after_seconds`. Kept as an enum anyway so
    templates/API responses have a stable vocabulary rather than each
    computing their own "online" wording."""

    ONLINE = "online"
    OFFLINE = "offline"
    # No event has ever been received for this honeypot — distinct from
    # OFFLINE, which means it was seen before and has since gone quiet.
    NEVER_SEEN = "never_seen"


class Honeypot(Base):
    __tablename__ = "honeypots"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    company: Mapped[Company] = relationship(back_populates="honeypots", lazy="joined")

    # e.g. "acme-honey1" — the RPI hostname convention from the install
    # runbook (<firma>-honey<n>), shown as this honeypot's display name.
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    # Free text — physical site/location note ("acme HQ, server room"), not
    # structured.
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Last IP an ingest request for this honeypot arrived from — informational
    # only (honeypots typically sit behind NetBird/VPN, so this is rarely a
    # public IP).
    last_seen_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Per-honeypot bearer credential for POST /api/ingest/events, alternative
    # to the shared INGEST_TOKEN — same "shared token as bootstrap, per-
    # resource token as the real credential" shape as debcontrol's
    # INFORM_TOKEN/per-user API tokens. Only the SHA-256 hash is stored.
    ingest_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)

    notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    last_seen_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)

    events: Mapped[list[HoneypotEvent]] = relationship(
        back_populates="honeypot", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Honeypot(id={self.id!r}, hostname={self.hostname!r})"
