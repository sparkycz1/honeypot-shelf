"""A honeypot's History tab — one time-ordered list of what happened to
it, merged from the records Honeypot Shelf already keeps:

- `note` — notes people added (`HoneypotNote`);
- `update_run` — system update runs and their outcome (`HoneypotUpdateRun`);
- `reachability` — the moments it stopped / started answering the
  reachability check (transitions in `HoneypotReachabilitySample`, found
  with a `LAG()` window, never by loading every per-minute sample);
- `audit` — what people and schedules did to it (`AuditLogEntry` rows
  targeting this honeypot), **only for a superadmin** — the History tab
  itself is open to every account that may see the honeypot, and the audit
  log is a superadmin page. Read-only actions (`*.view`, `*.browse`) are
  left out, and so are the note add/delete entries (the note itself is
  already there).

What attackers did is not here: that is the Activity tab and the Events
page.

Used by `GET /honeypots/{id}/history` and
`GET /api/v1/honeypots/{id}/timeline`. Each event carries an English
`summary` (API) plus the structured fields the page renders in the
viewer's language.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, not_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_note import HoneypotNote
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus

# The ranges the History tab offers, in days.
TIMELINE_RANGES = (1, 7, 30, 90, 365)
DEFAULT_RANGE_DAYS = 30
# Per source, and for the merged list — a page, not an export.
MAX_EVENTS = 300

TIMELINE_KINDS = ("note", "update_run", "reachability", "audit")


@dataclass
class TimelineEvent:
    at: datetime
    kind: str
    summary: str
    # "ok" / "error" / "warn" / None — the page's badge colour.
    outcome: str | None = None
    actor: str | None = None
    detail: str | None = None
    link: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "kind": self.kind,
            "summary": self.summary,
            "outcome": self.outcome,
            "actor": self.actor,
            "detail": self.detail,
            "link": self.link,
            "data": self.data,
        }


@dataclass
class Timeline:
    days: int
    since: datetime
    events: list[TimelineEvent]
    truncated: bool
    includes_audit: bool
    includes_updates: bool = True


def normalize_days(days: int | str | None) -> int:
    try:
        value = int(days) if days is not None else DEFAULT_RANGE_DAYS
    except (TypeError, ValueError):
        return DEFAULT_RANGE_DAYS
    return value if value in TIMELINE_RANGES else DEFAULT_RANGE_DAYS


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _update_run_event(honeypot: Honeypot, run: HoneypotUpdateRun) -> TimelineEvent:
    status = run.status.value
    outcome = {
        UpdateRunStatus.SUCCEEDED: "ok",
        UpdateRunStatus.FAILED: "error",
    }.get(run.status, "warn")
    at = run.finished_at or run.started_at or run.created_at
    return TimelineEvent(
        at=_utc(at),
        kind="update_run",
        summary=f"System update ({run.strategy.value}) {status}"
        + (f": {run.error}" if run.error else ""),
        outcome=outcome,
        detail=run.error,
        link=f"/honeypots/{honeypot.id}/updates/{run.id}",
        data={
            "status": status,
            "strategy": run.strategy.value,
            "run_id": str(run.id),
            "rollback": run.rollback_of_run_id is not None,
        },
    )


async def _reachability_transitions(
    db: AsyncSession, honeypot_id: uuid.UUID, since: datetime
) -> list[TimelineEvent]:
    previous = (
        func.lag(HoneypotReachabilitySample.reachable)
        .over(order_by=HoneypotReachabilitySample.checked_at)
        .label("previous")
    )
    ordered = (
        select(
            HoneypotReachabilitySample.checked_at,
            HoneypotReachabilitySample.reachable,
            previous,
        )
        .where(
            HoneypotReachabilitySample.honeypot_id == honeypot_id,
            HoneypotReachabilitySample.checked_at >= since,
        )
        .subquery()
    )
    result = await db.execute(
        select(ordered.c.checked_at, ordered.c.reachable)
        .where(ordered.c.previous.is_not(None), ordered.c.previous != ordered.c.reachable)
        .order_by(ordered.c.checked_at.desc())
        .limit(MAX_EVENTS)
    )
    return [
        TimelineEvent(
            at=_utc(checked_at),
            kind="reachability",
            summary="Reachable again" if reachable else "Stopped responding (unreachable)",
            outcome="ok" if reachable else "error",
            data={"reachable": bool(reachable)},
        )
        for checked_at, reachable in result.all()
    ]


async def _notes(db: AsyncSession, honeypot_id: uuid.UUID, since: datetime) -> list[TimelineEvent]:
    notes = await db.execute(
        select(HoneypotNote)
        .where(HoneypotNote.honeypot_id == honeypot_id, HoneypotNote.created_at >= since)
        .order_by(HoneypotNote.created_at.desc())
        .limit(MAX_EVENTS)
    )
    return [
        TimelineEvent(
            at=_utc(note.created_at),
            kind="note",
            summary=f"Note by {note.author}: {note.body}",
            actor=note.author,
            detail=note.body,
            data={"note_id": str(note.id)},
        )
        for note in notes.scalars().all()
    ]


async def _audited_actions(
    db: AsyncSession, honeypot_id: uuid.UUID, since: datetime
) -> list[TimelineEvent]:
    entries = await db.execute(
        select(AuditLogEntry)
        .where(
            AuditLogEntry.target_id == str(honeypot_id),
            AuditLogEntry.target_type == "honeypot",
            AuditLogEntry.created_at >= since,
            not_(AuditLogEntry.action.like("%.view")),
            not_(AuditLogEntry.action.like("%.browse")),
            # A manual "refresh now" and following a log live are look-ups
            # too: they change nothing on the honeypot.
            not_(AuditLogEntry.action.like("%.refresh")),
            not_(AuditLogEntry.action.like("honeypot.logs.follow%")),
            not_(AuditLogEntry.action.like("honeypot.note.%")),
        )
        .order_by(AuditLogEntry.created_at.desc())
        .limit(MAX_EVENTS)
    )
    events = []
    for entry in entries.scalars().all():
        data: dict[str, Any] = {"action": entry.action, "outcome": entry.outcome.value}
        duration = (entry.details or {}).get("duration_seconds")
        if entry.action == _TERMINAL_CLOSE and isinstance(duration, int | float):
            data["duration_seconds"] = duration
        events.append(
            TimelineEvent(
                at=_utc(entry.created_at),
                kind="audit",
                summary=entry.summary,
                outcome="ok" if entry.outcome == AuditOutcome.SUCCESS else "error",
                actor=entry.actor,
                data=data,
            )
        )
    return _merge_terminal_sessions(events)


_TERMINAL_OPEN = "honeypot.terminal.open"
_TERMINAL_CLOSE = "honeypot.terminal.close"
TERMINAL_SESSION = "honeypot.terminal.session"
# How far the logged "open" may sit from where its "close" says the session
# began (close time minus duration) and still be the same session.
_SESSION_MATCH_SECONDS = 15


def _merge_terminal_sessions(events: list[TimelineEvent]) -> list[TimelineEvent]:
    """One entry per terminal session instead of an "opened" and a "closed"
    one: the close carries the duration, so it becomes the session — placed
    at the moment it started — and the matching open is dropped. An open
    with no close yet (still running, or the close was never written)
    stays as it is. `events` is newest first, and stays so."""
    opens = [e for e in events if e.data.get("action") == _TERMINAL_OPEN]
    dropped: set[int] = set()
    for event in events:
        duration = event.data.get("duration_seconds")
        if event.data.get("action") != _TERMINAL_CLOSE or duration is None:
            continue
        started = event.at - timedelta(seconds=float(duration))
        match = next(
            (
                o
                for o in opens
                if id(o) not in dropped
                and o.actor == event.actor
                and abs((o.at - started).total_seconds()) <= _SESSION_MATCH_SECONDS
            ),
            None,
        )
        if match is not None:
            dropped.add(id(match))
        event.at = started
        event.data["action"] = TERMINAL_SESSION
        event.summary = f"Terminal session ({float(duration):.0f}s)"
    merged = [e for e in events if id(e) not in dropped]
    merged.sort(key=lambda e: e.at, reverse=True)
    return merged


async def load_timeline(
    db: AsyncSession,
    honeypot: Honeypot,
    *,
    days: int = DEFAULT_RANGE_DAYS,
    include_audit: bool,
    include_updates: bool = True,
    kinds: set[str] | None = None,
) -> Timeline:
    """`honeypot` must already be access-checked by the caller. `kinds`
    limits the sources (None = all). `include_updates` is False for an
    account that may only read the honeypot: update runs are not its
    business."""
    days = normalize_days(days)
    since = datetime.now(UTC) - timedelta(days=days)
    wanted = set(TIMELINE_KINDS) if not kinds else set(kinds) & set(TIMELINE_KINDS)
    if not include_updates:
        wanted.discard("update_run")
    events: list[TimelineEvent] = []

    if "note" in wanted:
        events.extend(await _notes(db, honeypot.id, since))
    if "update_run" in wanted:
        runs = await db.execute(
            select(HoneypotUpdateRun)
            .where(
                HoneypotUpdateRun.honeypot_id == honeypot.id,
                HoneypotUpdateRun.created_at >= since,
            )
            .order_by(HoneypotUpdateRun.created_at.desc())
            .limit(MAX_EVENTS)
        )
        events.extend(_update_run_event(honeypot, run) for run in runs.scalars().all())
    if "reachability" in wanted:
        events.extend(await _reachability_transitions(db, honeypot.id, since))
    if include_audit and "audit" in wanted:
        events.extend(await _audited_actions(db, honeypot.id, since))

    events.sort(key=lambda e: e.at, reverse=True)
    return Timeline(
        days=days,
        since=since,
        events=events[:MAX_EVENTS],
        truncated=len(events) > MAX_EVENTS,
        includes_audit=include_audit,
        includes_updates=include_updates,
    )
