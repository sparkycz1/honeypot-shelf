"""One row per company per day: a cheap, pre-aggregated point for the
Dashboard's trend chart, written by a daily Celery Beat job
(`app.tasks.jobs.record_company_snapshots`) rather than computed from
`honeypot_events`/`honeypots` on every page load. Purged after
`AppSettings.dashboard_trends_retention_days` — see that column's
docstring. Mirrors debcontrol's `FleetSnapshot`, scoped to a company
instead of the whole (single-tenant) fleet, plus this project's own
event-ingestion counts (`honeypots_online`/`event_count`, which have no
debcontrol equivalent — see `app.services.honeypot_status`).

Two independent notions of "online" are both captured here — same
distinction `app.db.models.honeypot`'s module docstring draws:
`honeypots_online` is the OpenCanary-event signal (`Honeypot.last_seen_at`
recent enough); `needs_updates`/`needs_security_updates`/`needs_reboot`
mirror debcontrol's SSH-management-plane facts
(`Honeypot.is_reachable`/`upgradable_count`/etc, via
`app.services.company_stats.compute_company_stats`).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Date, ForeignKey, Integer, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CompanySnapshot(Base):
    __tablename__ = "company_snapshots"
    __table_args__ = (UniqueConstraint("company_id", "snapshot_date", name="uq_company_snapshot"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)

    # --- This project's own event-ingestion counts ---
    honeypot_count: Mapped[int] = mapped_column(Integer, nullable=False)
    honeypots_online: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- SSH-management-plane facts, mirroring debcontrol's FleetSnapshot ---
    honeypots_reachable: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    needs_updates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    needs_security_updates: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    needs_reboot: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"CompanySnapshot(company_id={self.company_id!r}, "
            f"snapshot_date={self.snapshot_date!r}, event_count={self.event_count!r})"
        )
