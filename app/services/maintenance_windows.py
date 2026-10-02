"""Maintenance windows — see `app.db.models.maintenance_window` for what a
window is. This module answers "is this honeypot in maintenance right
now" for notifications (`app.services.notifications`), scheduled tasks
(`app.scheduling.jobs`) and the honeypot page's badge, and saves a window
from its validated schema for both the web form and the REST API. Ported
from debcontrol.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.notification_log import NotificationKind
from app.schemas.maintenance_window import MaintenanceWindowSave

WindowState = Literal["active", "upcoming", "ended"]


def _utc(value: datetime) -> datetime:
    """Normalize a stored timestamp — SQLite (tests) hands back naive UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def window_state(window: MaintenanceWindow, now: datetime | None = None) -> WindowState:
    now = now or datetime.now(UTC)
    if _utc(window.ends_at) <= now:
        return "ended"
    if _utc(window.starts_at) > now:
        return "upcoming"
    return "active"


def covers(window: MaintenanceWindow, honeypot: Honeypot) -> bool:
    """`all_honeypots` means every honeypot in the window's own company,
    never across companies — the same rule a scheduled task's "All
    honeypots" follows (`app.scheduling.targets`)."""
    if window.all_honeypots:
        return any(c.id == window.owner_company_id for c in honeypot.companies)
    return any(h.id == honeypot.id for h in window.honeypots)


async def active_windows(db: AsyncSession, now: datetime | None = None) -> list[MaintenanceWindow]:
    """Every window in effect at `now` — few rows even on a large fleet (the
    `ends_at` index skips all past windows)."""
    now = now or datetime.now(UTC)
    result = await db.execute(
        select(MaintenanceWindow).where(
            MaintenanceWindow.ends_at > now, MaintenanceWindow.starts_at <= now
        )
    )
    return list(result.scalars().all())


async def active_window_for(
    db: AsyncSession, honeypot: Honeypot, now: datetime | None = None
) -> MaintenanceWindow | None:
    """The (first) active window covering `honeypot` — the honeypot page's
    "in maintenance" badge."""
    for window in await active_windows(db, now):
        if covers(window, honeypot):
            return window
    return None


async def muting_window(
    db: AsyncSession, honeypot: Honeypot, kind: NotificationKind, now: datetime | None = None
) -> MaintenanceWindow | None:
    """The active window that mutes a `kind` notification about `honeypot`,
    if any. "Unavailable"/"available again" are muted by any covering
    window; a new-alert notification only by one with `mute_alerts` set;
    a test send never."""
    if kind == NotificationKind.TEST:
        return None
    for window in await active_windows(db, now):
        if not covers(window, honeypot):
            continue
        if kind == NotificationKind.ALERT and not window.mute_alerts:
            continue
        return window
    return None


async def honeypots_paused_for_scheduling(
    db: AsyncSession, honeypots: list[Honeypot], now: datetime | None = None
) -> set[uuid.UUID]:
    """Ids of those `honeypots` inside an active window that also pauses
    scheduled tasks — one query for the active windows, then in-memory
    matching (a handful of windows at most)."""
    pausing = [w for w in await active_windows(db, now) if w.pause_scheduled_tasks]
    if not pausing:
        return set()
    return {h.id for h in honeypots if any(covers(w, h) for w in pausing)}


async def apply_window_data(
    db: AsyncSession, window: MaintenanceWindow, data: MaintenanceWindowSave
) -> None:
    """Copy validated `data` onto `window` (new or existing); the caller
    checks the company scope first and adds/commits. Listed honeypots
    outside the window's company (or that no longer exist) are dropped."""
    window.owner_company_id = data.owner_company_id
    window.name = data.name
    window.reason = data.reason
    window.starts_at = data.starts_at
    window.ends_at = data.ends_at
    window.all_honeypots = data.all_honeypots
    window.pause_scheduled_tasks = data.pause_scheduled_tasks
    window.mute_alerts = data.mute_alerts
    honeypots: list[Honeypot] = []
    if not data.all_honeypots and data.honeypot_ids:
        result = await db.execute(
            select(Honeypot).where(
                Honeypot.id.in_(data.honeypot_ids),
                Honeypot.companies.any(Company.id == data.owner_company_id),
            )
        )
        honeypots = list(result.scalars().all())
    window.honeypots = honeypots


def window_summary(window: MaintenanceWindow) -> str:
    """English scope description for audit summaries."""
    company = window.owner_company.name if window.owner_company else "?"
    if window.all_honeypots:
        return f"all honeypots of {company}"
    return ", ".join(h.name for h in window.honeypots) or "no honeypots"
