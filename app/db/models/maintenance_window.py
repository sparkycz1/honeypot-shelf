"""A maintenance window: a time range of planned work on some honeypots —
"we're re-flashing the Brno devices Saturday 02:00-04:00".

Like a `ScheduledTask`, every window belongs to exactly one company
(`owner_company_id`), and covers either every honeypot in that company
(`all_honeypots`) or the listed honeypots. While a window is active:

- "unavailable" / "available again" notifications about a covered
  honeypot are muted — recorded in the delivery history as muted, naming
  the window, never silently dropped;
- new-alert notifications are muted only when `mute_alerts` is set — an
  alert is a security signal, so by default it still goes out;
- scheduled tasks skip covered honeypots when `pause_scheduled_tasks` is
  set (skipped for that run, not queued).

Ported from debcontrol, where windows are scoped to machine groups instead.
See `app.services.maintenance_windows` for the matching logic.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Column, ForeignKey, Index, String, Table, Text, false, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

maintenance_window_honeypots = Table(
    "maintenance_window_honeypots",
    Base.metadata,
    Column("window_id", ForeignKey("maintenance_windows.id", ondelete="CASCADE"), primary_key=True),
    Column("honeypot_id", ForeignKey("honeypots.id", ondelete="CASCADE"), primary_key=True),
)


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    __table_args__ = (
        # Every notification and every scheduled run asks "which windows
        # are active right now" — i.e. not yet ended; ends_at bounds that
        # scan as history grows.
        Index("ix_maintenance_windows_ends_at", "ends_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    starts_at: Mapped[datetime] = mapped_column(nullable=False)
    ends_at: Mapped[datetime] = mapped_column(nullable=False)
    all_honeypots: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    pause_scheduled_tasks: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    mute_alerts: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    # Kept as text, not a user FK: the window (and its audit meaning)
    # outlives the account that scheduled it.
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    owner_company: Mapped[Company] = relationship(lazy="selectin")
    honeypots: Mapped[list[Honeypot]] = relationship(
        secondary=maintenance_window_honeypots, lazy="selectin", order_by="Honeypot.name"
    )


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.honeypot import Honeypot
