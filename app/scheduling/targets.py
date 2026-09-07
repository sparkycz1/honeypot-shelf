"""Resolving a `ScheduledTask`'s target into the actual list of honeypots it
applies to right now — shared by the job that executes a schedule
(`app.scheduling.jobs`) and the web UI (to show "applies to N honeypot(s)").

Also the single-`<select>` encoding used by the "New/edit scheduled task"
form (`encode_target`/`decode_target`) — one dropdown listing "All
honeypots (in this company)", every honeypot, is a much simpler form than a
target-type radio plus a conditionally-relevant select, and needs no
client-side JS to keep the irrelevant one from being submitted too.

**Every `ScheduledTask` belongs to exactly one company**
(`ScheduledTask.owner_company_id`) — unlike debcontrol, where "All
machines" meant the whole (single-tenant) fleet, `ALL_HONEYPOTS` here means
"every honeypot in this schedule's own company", never across companies.
That's set once at creation (`owner_company_id` = the target honeypot's
company, or the company explicitly chosen for an `ALL_HONEYPOTS` schedule)
and is what all scoping below checks against — simpler than debcontrol's
`allowed_group_ids` lookup, since there's nothing opt-in to resolve.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.scope import has_company_access
from app.db.models.honeypot import Honeypot
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.user import User

_ALL_HONEYPOTS_VALUE = "all"
_HONEYPOT_PREFIX = "honeypot:"


def encode_target(target_type: ScheduleTargetType, target_honeypot_id: uuid.UUID | None) -> str:
    if target_type == ScheduleTargetType.HONEYPOT and target_honeypot_id is not None:
        return f"{_HONEYPOT_PREFIX}{target_honeypot_id}"
    return _ALL_HONEYPOTS_VALUE


def decode_target(raw: str) -> tuple[ScheduleTargetType, uuid.UUID | None]:
    """Raises ValueError on anything malformed — the `<select>` this comes
    from is server-rendered, so a bad value here means a tampered request,
    not a normal user mistake."""
    if raw == _ALL_HONEYPOTS_VALUE:
        return ScheduleTargetType.ALL_HONEYPOTS, None
    if raw.startswith(_HONEYPOT_PREFIX):
        return ScheduleTargetType.HONEYPOT, uuid.UUID(raw[len(_HONEYPOT_PREFIX) :])
    raise ValueError(f'Invalid target "{raw}".')


async def resolve_target_honeypots(db: AsyncSession, task: ScheduledTask) -> list[Honeypot]:
    """Every honeypot `task` currently targets. Resolved fresh each time
    (never cached on the task) — a company's honeypots can change between
    schedule creation and the next time it fires."""
    if task.target_type == ScheduleTargetType.ALL_HONEYPOTS:
        result = await db.execute(
            select(Honeypot).where(Honeypot.company_id == task.owner_company_id)
        )
        return list(result.scalars().all())

    if task.target_type == ScheduleTargetType.HONEYPOT:
        if task.target_honeypot_id is None:
            return []
        honeypot = await db.get(Honeypot, task.target_honeypot_id)
        return [honeypot] if honeypot is not None else []

    return []


def target_within_scope(user: User, owner_company_id: uuid.UUID, *, write: bool = True) -> bool:
    """Whether `user`'s company scope covers a schedule owned by
    `owner_company_id`. `write=True` (the default) is what create/edit
    checks — a stored schedule runs on its cron expression with no
    "current user" at all (see `app.scheduling.jobs`), so execution-time
    scoping would be meaningless: the boundary is enforced against whoever
    writes the schedule. Pass `write=False` for a read-only check (listing/
    viewing) — a company's `READ`-only users can still see its schedules,
    just not create/edit/run/delete them (enforced separately by
    `require_write` on those routes)."""
    return has_company_access(user, owner_company_id, write=write)


def task_within_scope(user: User, task: ScheduledTask) -> bool:
    """`target_within_scope` for an already-stored task, read-only — used
    to decide whether a schedule is listed to, and openable by, this
    account."""
    return target_within_scope(user, task.owner_company_id, write=False)
