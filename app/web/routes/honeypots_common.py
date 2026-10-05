"""What the `/honeypots` route modules share: the write-tier dependencies,
look-ups that 404 outside the account's companies, the tab list, and the
small queries more than one of them needs. No routes here — see
`app.web.routes.honeypots` for how the modules are put together. Same
layout as debcontrol's `machines_*` modules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_write
from app.auth.scope import (
    can_write_honeypot,
    honeypots_visible_to,
)
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.honeypot_service import HoneypotService
from app.db.models.honeypot_tag import Tag
from app.db.models.user import User
from app.services import (
    monitoring_history,
)
from app.services.honeypot_status import as_aware_utc
from app.services.monitoring_history import TimeWindow
from app.web.templating import t
from app.web.time_window import window_query


def honeypots_router() -> APIRouter:
    """One area's router. Each area module makes its own and
    `app.web.routes.honeypots` includes them in order."""
    return APIRouter(prefix="/honeypots")


# debcontrol gates updates/power/terminal behind their own separate
# Permissions; this app has only one write tier (READ_WRITE on the
# honeypot's company — see app.db.models.user's module docstring), so all
# four collapse into the same dependency. Kept as separate names anyway —
# matching every route below exactly the way it matched debcontrol's own
# four — so a future re-introduction of finer-grained tiers touches only
# this one spot.
need_manage = Depends(require_write)


need_updates = Depends(require_write)


need_power = Depends(require_write)


need_terminal = Depends(require_write)


def _honeypot_tabs(request: Request, honeypot: Honeypot, user: User) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this honeypot's own
    pages — same set and order everywhere, so `partials/_tabnav.html` always
    highlights the right one. Terminal is left out entirely for a
    read-only user, same as it was hidden inline before this page had
    tabs at all."""
    base = f"/honeypots/{honeypot.id}"
    tabs = [
        ("overview", t(request, "honeypots.tabs.overview"), base),
        ("monitoring", t(request, "honeypots.tabs.monitoring"), f"{base}/monitoring"),
        # Read-only too, unlike the write-gated tabs below — a read-only
        # account can already see what OpenCanary has actually caught on
        # this honeypot without being able to manage it.
        ("status", t(request, "honeypots.tabs.activity"), f"{base}/status"),
        # Read-only as well: what happened to the honeypot itself.
        ("history", t(request, "honeypots.tabs.history"), f"{base}/history"),
    ]
    if user.can_write():
        tabs.append(("updates", t(request, "honeypots.tabs.updates"), f"{base}/updates"))
        tabs.append(("terminal", t(request, "honeypots.tabs.terminal"), f"{base}/terminal"))
        # Logs/Config/Settings all share Terminal's write gate rather than
        # being available to a read-only account — see the "Logs" route's
        # own docstring for why.
        tabs.append(("logs", t(request, "honeypots.tabs.logs"), f"{base}/logs"))
        tabs.append(("config", t(request, "honeypots.tabs.config"), f"{base}/config"))
        # No separate "Power" tab any more — reboot/shut down live directly
        # on Overview now (see `honeypot_detail`'s own template), the same
        # one-page placement this honeypot's other one-off actions (test
        # connection, discover host key) already have, rather than a whole
        # tab for two buttons. `GET /{id}/power` itself still redirects
        # there for anyone with the old URL bookmarked/linked — see
        # `power_tab`.
        tabs.append(("settings", t(request, "honeypots.tabs.settings"), f"{base}/edit"))
    return tabs


async def _get_honeypot_or_404(honeypot_id: uuid.UUID, db: AsyncSession, user: User) -> Honeypot:
    """The honeypot, or a 404 — including when it exists but is outside
    `user`'s company scope (`app.services.access_scope`). 404, never
    403, for the same reason `app/web/routes/ai.py`'s `_get_conversation`
    uses one: a 403 would confirm that a honeypot with that id exists."""
    # `Honeypot.companies` is `lazy="selectin"` on the model already —
    # templates read `honeypot.companies` and the async ORM can't
    # lazy-load a relationship outside of an `await` (it would raise
    # MissingGreenlet during template rendering), so this relies on that
    # default loader strategy rather than an explicit `.options()` here.
    query = honeypots_visible_to(user)
    result = await db.execute(query.where(Honeypot.id == honeypot_id))
    honeypot = result.scalar_one_or_none()
    if honeypot is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found.")
    return honeypot


async def _get_writable_honeypot_or_404(
    honeypot_id: uuid.UUID, db: AsyncSession, user: User
) -> Honeypot:
    """`_get_honeypot_or_404`, then 403 for an account that may only read
    it — for everything a read-only account has no business with: changing
    the honeypot, and its packages and pending updates."""
    honeypot = await _get_honeypot_or_404(honeypot_id, db, user)
    if not can_write_honeypot(user, honeypot):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Read-only access.")
    return honeypot


async def _get_companies(db: AsyncSession, user: User) -> list[Company]:
    """The companies offered in the honeypot create/edit form's
    multi-select — every company for a superadmin; only the companies a
    company-scoped user can *write* (not merely read) for anyone else,
    since this is always a write-context form."""
    result = await db.execute(select(Company).order_by(Company.name))
    companies = list(result.scalars().all())
    if user.is_superadmin:
        return companies
    return [c for c in companies if user.can_write_company(c.id)]


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — the honeypot list's filter
    dropdown and the create/edit forms' autocomplete `<datalist>`. Not
    scoped by company access: a tag *name* existing isn't fleet
    data, and a restricted account typing a tag another honeypot happens to
    use just filters to nothing, the same as typing a free-text search
    term that doesn't match anything in scope."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def _get_service_counts(honeypot_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(func.count())
        .select_from(HoneypotService)
        .where(HoneypotService.honeypot_id == honeypot_id)
    )
    total = result.scalar_one()
    failed_result = await db.execute(
        select(func.count())
        .select_from(HoneypotService)
        .where(
            HoneypotService.honeypot_id == honeypot_id, HoneypotService.active_state == "failed"
        )
    )
    return {"total": total, "failed": failed_result.scalar_one()}


def _window_context(window: TimeWindow) -> dict[str, Any]:
    """What the chart templates need to stay on the same time window: the
    picker's state, the query string for links and the panel's own poll
    URL, and the two values the "Refresh now" POST sends back."""
    custom = window.is_custom and window.until is not None
    return {
        "time_ranges": monitoring_history.TIME_RANGES,
        "range_key": window.range_key,
        "window": window,
        "window_query": window_query(window),
        "window_start": window.since.isoformat() if custom else "",
        "window_end": window.until.isoformat() if custom and window.until else "",
    }


async def _build_monitoring_context(
    honeypot: Honeypot, window: TimeWindow, db: AsyncSession, user: User
) -> dict[str, Any]:
    """The Monitoring tab's own data, shared by the first-paint route, the
    auto-refresh/live-update panel route, and the "Refresh now" route —
    see partials/honeypot_monitoring_content.html's own comment for why
    these three routes all funnel through the one partial."""
    range_key = window.range_key
    since = window.since
    # `until` is None for a preset ("up to now"), so far in the future is
    # the same thing without a second code path.
    until = window.until or datetime.now(UTC) + timedelta(days=1)
    result = await db.execute(
        select(HoneypotMonitoringSample)
        .where(
            HoneypotMonitoringSample.honeypot_id == honeypot.id,
            HoneypotMonitoringSample.sampled_at >= since,
            HoneypotMonitoringSample.sampled_at <= until,
        )
        .order_by(HoneypotMonitoringSample.sampled_at)
        .limit(monitoring_history.MAX_RAW_SAMPLES)
    )
    samples = list(result.scalars().all())
    history = monitoring_history.build_monitoring_history(samples, range_key)

    reachability_result = await db.execute(
        select(HoneypotReachabilitySample)
        .where(
            HoneypotReachabilitySample.honeypot_id == honeypot.id,
            HoneypotReachabilitySample.checked_at >= since,
            HoneypotReachabilitySample.checked_at <= until,
        )
        .order_by(HoneypotReachabilitySample.checked_at)
        .limit(monitoring_history.MAX_RAW_SAMPLES)
    )
    reachability_samples = list(reachability_result.scalars().all())
    availability = monitoring_history.build_availability_history(reachability_samples, range_key)

    # One unified "last checked" for the whole tab, rather than a separate
    # timestamp per graph (CPU/RAM/OpenCanary all share one round trip's
    # `monitoring_updated_at`; Availability's own reachability check runs
    # independently) — the more recent of the two, so the header always
    # reflects whichever check actually ran most recently. Both need
    # `as_aware_utc` first: SQLite (tests) drops tzinfo on round-trip,
    # real Postgres columns never do (see app.services.honeypot_status).
    candidates = [
        as_aware_utc(t)
        for t in (honeypot.monitoring_updated_at, honeypot.last_ping_at)
        if t is not None
    ]
    last_checked_at = max(candidates) if candidates else None

    return {
        "honeypot": honeypot,
        "history": history,
        "availability": availability,
        **_window_context(window),
        "service_counts": await _get_service_counts(honeypot.id, db),
        # The whole services table is on the page (filtered and sorted
        # client-side, static/js/monitoring-chart.js) — a honeypot runs a
        # few dozen units, not thousands.
        "services": list(
            (
                await db.execute(
                    select(HoneypotService)
                    .where(HoneypotService.honeypot_id == honeypot.id)
                    .order_by(HoneypotService.unit)
                )
            ).scalars()
        ),
        "last_checked_at": last_checked_at,
        # "Refresh now" is a write action (`POST .../monitoring/refresh`).
        "can_refresh": can_write_honeypot(user, honeypot),
    }
