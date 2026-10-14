"""One month of what is planned and what happened: scheduled tasks'
runs, maintenance windows and update batches, day by day.

Shared by the calendar page (`app/web/routes/scheduling.py`) and the REST
API (`app/web/routes/api_v1_scheduling.py`). Days are days of the
instance's display time zone (`TZ`), the same one every timestamp in the
UI is shown in. Ported from debcontrol.

Scoped like the pages each entry links to: scheduled tasks the account
may see (`task_within_scope`), maintenance windows of companies it may
write, and update batches narrowed to the honeypots it may write
(`app.services.update_batches`' rule).

Everything is read, nothing is stored: a task's runs are computed from its
cron expression in its own time zone, so the calendar shows what the
schedule says — including, for the days already gone, when it was due.
"""

from __future__ import annotations

import calendar
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import Any

from croniter import croniter
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.scope import has_company_access, honeypots_writable_by
from app.core.config import get_settings
from app.core.timezones import zone
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.scheduling.targets import task_within_scope

KIND_TASK = "task"
KIND_WINDOW = "window"
KIND_BATCH = "batch"

# A task that runs more often than this in one day is shown once, with
# how many times ("every 5 minutes" is one line, not 288).
_MAX_RUNS_LISTED_PER_DAY = 3
# Stop expanding one task's cron after this many runs in the month.
_MAX_RUNS_PER_TASK = 50_000
_MAX_BATCHES = 500
_MONTH_RE = re.compile(r"(\d{4})-(\d{2})", re.ASCII)


@dataclass(frozen=True)
class Entry:
    kind: str
    at: datetime | None
    label: str
    href: str
    # task: how many runs that day (when shown as one line); batch: failed runs.
    count: int = 0
    # task: disabled; batch: something failed; window: pauses scheduled tasks.
    flag: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "at": self.at.isoformat() if self.at else None,
            "label": self.label,
            "href": self.href,
            "count": self.count,
            "flag": self.flag,
        }


@dataclass
class Day:
    day: date
    in_month: bool
    is_today: bool
    entries: list[Entry] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"date": self.day.isoformat(), "entries": [e.as_dict() for e in self.entries]}


@dataclass
class Month:
    year: int
    month: int
    weeks: list[list[Day]]

    @property
    def key(self) -> str:
        return f"{self.year:04d}-{self.month:02d}"

    @property
    def previous_key(self) -> str:
        year, month = (self.year - 1, 12) if self.month == 1 else (self.year, self.month - 1)
        return f"{year:04d}-{month:02d}"

    @property
    def next_key(self) -> str:
        year, month = (self.year + 1, 1) if self.month == 12 else (self.year, self.month + 1)
        return f"{year:04d}-{month:02d}"

    @property
    def days(self) -> list[Day]:
        return [day for week in self.weeks for day in week if day.in_month]


def parse_month(value: str | None, today: date) -> tuple[int, int]:
    """`YYYY-MM` -> (year, month); the current month for anything else."""
    match = _MONTH_RE.fullmatch((value or "").strip())
    if match is not None:
        year, month = int(match.group(1)), int(match.group(2))
        if 2000 <= year <= 2100 and 1 <= month <= 12:
            return year, month
    return today.year, today.month


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def task_runs(task: ScheduledTask, start: datetime, end: datetime) -> list[datetime]:
    """Every time `task` is due in [start, end), as UTC datetimes."""
    try:
        iterator = croniter(
            task.cron_expression,
            (start - timedelta(seconds=1)).astimezone(zone(task.timezone or "UTC")),
        )
    except (ValueError, KeyError):
        return []
    runs: list[datetime] = []
    while len(runs) < _MAX_RUNS_PER_TASK:
        try:
            due = iterator.get_next(datetime).astimezone(UTC)
        except (ValueError, KeyError):
            break
        if due >= end:
            break
        runs.append(due)
    return runs


@dataclass(frozen=True)
class _Span:
    """The month being built: its days, and where it starts and ends."""

    days: dict[date, Day]
    first: date
    after_last: date
    start: datetime
    end: datetime
    display: tzinfo

    def local_day(self, moment: datetime) -> date:
        return _aware(moment).astimezone(self.display).date()


async def _add_tasks(db: AsyncSession, user: User, span: _Span) -> None:
    result = await db.execute(select(ScheduledTask).order_by(ScheduledTask.name))
    for task in result.scalars().all():
        if not task_within_scope(user, task):
            continue
        per_day: dict[date, list[datetime]] = {}
        for due in task_runs(task, span.start, span.end):
            per_day.setdefault(span.local_day(due), []).append(due)
        href = f"/scheduling/{task.id}/edit"
        for day, runs in per_day.items():
            if day not in span.days:
                continue
            if len(runs) > _MAX_RUNS_LISTED_PER_DAY:
                span.days[day].entries.append(
                    Entry(KIND_TASK, runs[0], task.name, href, len(runs), not task.is_enabled)
                )
            else:
                span.days[day].entries.extend(
                    Entry(KIND_TASK, due, task.name, href, 1, not task.is_enabled)
                    for due in runs
                )


async def _add_windows(db: AsyncSession, user: User, span: _Span) -> None:
    windows = await db.execute(
        select(MaintenanceWindow)
        .where(MaintenanceWindow.starts_at < span.end, MaintenanceWindow.ends_at > span.start)
        .order_by(MaintenanceWindow.starts_at)
    )
    for window in windows.scalars().all():
        if not has_company_access(user, window.owner_company_id, write=True):
            continue
        begins, finishes = _aware(window.starts_at), _aware(window.ends_at)
        day = max(span.local_day(begins), span.first)
        last = min(
            span.local_day(finishes - timedelta(seconds=1)), span.after_last - timedelta(days=1)
        )
        while day <= last:
            span.days[day].entries.append(
                Entry(
                    KIND_WINDOW,
                    begins if day == span.local_day(begins) else None,
                    window.name,
                    f"/scheduling/maintenance/{window.id}/edit",
                    flag=window.pause_scheduled_tasks,
                )
            )
            day += timedelta(days=1)


async def _add_batches(db: AsyncSession, user: User, span: _Span) -> None:
    writable_ids = honeypots_writable_by(user).with_only_columns(Honeypot.id)
    started = func.min(HoneypotUpdateRun.created_at)
    failed = func.sum(case((HoneypotUpdateRun.status == UpdateRunStatus.FAILED, 1), else_=0))
    batches = await db.execute(
        select(HoneypotUpdateRun.batch_id, started, func.count(), failed)
        .where(
            HoneypotUpdateRun.batch_id.is_not(None),
            HoneypotUpdateRun.honeypot_id.in_(writable_ids),
            HoneypotUpdateRun.created_at >= span.start,
            HoneypotUpdateRun.created_at < span.end,
        )
        .group_by(HoneypotUpdateRun.batch_id)
        .having(func.count() > 1)
        .order_by(started)
        .limit(_MAX_BATCHES)
    )
    for batch_id, began, total, failures in batches.all():
        if not isinstance(batch_id, uuid.UUID) or began is None:
            continue
        day = span.local_day(began)
        if day in span.days:
            span.days[day].entries.append(
                Entry(
                    KIND_BATCH,
                    _aware(began),
                    str(total),
                    f"/batches/{batch_id}",
                    count=int(failures or 0),
                    flag=bool(failures),
                )
            )


async def build(db: AsyncSession, user: User, year: int, month: int) -> Month:
    display = zone(get_settings().tz)
    today = datetime.now(display).date()
    grid = calendar.Calendar(firstweekday=0).monthdatescalendar(year, month)
    days: dict[date, Day] = {}
    weeks: list[list[Day]] = []
    for week in grid:
        row = []
        for day in week:
            cell = Day(day=day, in_month=day.month == month, is_today=day == today)
            days[day] = cell
            row.append(cell)
        weeks.append(row)

    first = date(year, month, 1)
    after_last = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    span = _Span(
        days=days,
        first=first,
        after_last=after_last,
        start=datetime(first.year, first.month, first.day, tzinfo=display).astimezone(UTC),
        end=datetime(
            after_last.year, after_last.month, after_last.day, tzinfo=display
        ).astimezone(UTC),
        display=display,
    )
    await _add_tasks(db, user, span)
    await _add_windows(db, user, span)
    await _add_batches(db, user, span)

    for cell in days.values():
        cell.entries.sort(key=lambda e: (e.at is not None, e.at or span.start, e.kind, e.label))
    return Month(year=year, month=month, weeks=weeks)
