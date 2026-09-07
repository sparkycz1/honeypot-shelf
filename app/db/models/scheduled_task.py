"""A user-defined, cron-scheduled action against a honeypot, a company, or
"All honeypots" — see `app.scheduling` for the action registry and the
background jobs that evaluate and run these.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.pg_enum import pg_enum


class ScheduleTargetType(enum.StrEnum):
    HONEYPOT = "honeypot"
    COMPANY = "company"
    ALL_HONEYPOTS = "all_honeypots"


class ScheduledTask(Base):
    """One recurring action: run `action` (a key into the schedulable-action
    registry, `app.scheduling.actions`) against `target_type`'s honeypots,
    on the schedule described by `cron_expression` (standard 5-field cron,
    interpreted in UTC).

    Adding a brand new kind of action to the app doesn't require any change
    here — it only needs a `ScheduledActionSpec` registered in
    `app.scheduling.builtin_actions`, and it becomes selectable in the
    "New scheduled task" form automatically.

    Unlike debcontrol, a schedule is always implicitly scoped to one
    company — `target_company_id` (or, for a single-honeypot target,
    `target_honeypot.company_id`) is who "owns" it, checked against the
    creating user the same way any other write is
    (`app.auth.scope.ensure_company_access`). "All honeypots" for a
    non-superadmin means "all honeypots in *my* company", never the whole
    fleet — see `app.scheduling.targets`.
    """

    __tablename__ = "scheduled_tasks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Key into app.scheduling.actions' registry (e.g. "system_update",
    # "check_updates", "reboot", "shutdown") — deliberately a plain string,
    # not a native enum, so a new action can be registered without a migration.
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    # Per-action options, e.g. {"strategy": "dist_upgrade"} for system_update.
    # Shape is defined by that action's `ScheduledActionParam`s, not enforced
    # by the DB.
    action_params: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    target_type: Mapped[ScheduleTargetType] = mapped_column(
        pg_enum(ScheduleTargetType, name="schedule_target_type"), nullable=False
    )
    # Exactly one of these is set, matching target_type — enforced in the
    # route/schema layer, not via a DB constraint (SQLite in tests doesn't
    # make a CHECK constraint across nullable FKs pleasant, and there's only
    # ever one writer: the scheduling form). For ALL_HONEYPOTS, neither is
    # set — `owner_company_id` below is what scopes it instead.
    target_honeypot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=True
    )
    target_honeypot: Mapped[Honeypot | None] = relationship()

    # The company this schedule belongs to — always set (unlike
    # target_honeypot_id/nothing for ALL_HONEYPOTS, this is set for every
    # target_type, including HONEYPOT/COMPANY where it's redundant with the
    # target's own company but kept denormalized so every scheduled-task
    # query can filter by company without a join).
    owner_company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_company: Mapped[Company] = relationship()

    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Denormalized so the per-minute tick (`app.scheduling.jobs.run_due_scheduled_tasks`)
    # is a single indexed `WHERE next_run_at <= now` query instead of every
    # tick re-parsing every enabled task's cron expression. Recomputed on
    # create/edit and after every run.
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Short human-readable outcome of the most recent run (e.g. "Triggered
    # for 3 honeypot(s), 1 skipped."), not a full log — there's no per-run
    # row for scheduled triggers, same reasoning as power actions: the
    # underlying job (update run / power command) already records what
    # matters, this is just "did the schedule itself fire".
    last_run_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"ScheduledTask(id={self.id!r}, name={self.name!r}, "
            f"action={self.action!r}, cron={self.cron_expression!r})"
        )
