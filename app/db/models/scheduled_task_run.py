"""One firing of a `ScheduledTask` — a persistent history of what happened
each time a schedule fired, alongside `ScheduledTask.last_run_at`/
`last_run_summary` (kept for the cheap "when did this last run" list-page
column; this table is the fuller history/retry view). See
`app.scheduling.jobs._run_scheduled_task`, the only writer.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.scheduled_task import ScheduledTask
from app.db.pg_enum import pg_enum


class ScheduledTaskRunOutcome(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class ScheduledTaskRun(Base):
    """One row per time a schedule actually fired — whether from the
    per-minute tick or a manual "Run now" — recording what its action's
    `run()` reported, or the exception it raised. Deliberately not a full
    per-honeypot log: the underlying action's own records (e.g.
    `HoneypotUpdateRun`) already cover that; this is "did the schedule
    itself fire, and did resolving/dispatching its action succeed"."""

    __tablename__ = "scheduled_task_runs"
    __table_args__ = (Index("ix_scheduled_task_runs_task_id_fired_at", "task_id", "fired_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scheduled_tasks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    task: Mapped[ScheduledTask] = relationship()

    fired_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    outcome: Mapped[ScheduledTaskRunOutcome] = mapped_column(
        pg_enum(ScheduledTaskRunOutcome, name="scheduled_task_run_outcome"), nullable=False
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    # Populated only on FAILURE — the exception's str(), for debugging a
    # provisioning-style failure (e.g. every target skipped, a DB error)
    # without digging through worker logs.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"ScheduledTaskRun(id={self.id!r}, task_id={self.task_id!r}, "
            f"outcome={self.outcome!r}, fired_at={self.fired_at!r})"
        )
