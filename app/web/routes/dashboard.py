"""The Dashboard — the one page every user lands on after login. Per the
product brief: every user (whatever their access level) sees the *sum*
across every company they have access to; a superadmin sees the sum
across every company, plus a per-company breakdown — now also shown to a
non-superadmin holding membership in more than one company, since "sum
across your companies" stops being obviously readable once there's more
than one of them.

Scoped entirely through `app.auth.scope.visible_company_ids` — `None` for
a superadmin (no filter, i.e. every company), a set of ids otherwise (any
number, including a single one — the common case).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import get_current_user
from app.auth.scope import visible_company_ids
from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.canary_activity_history import MAX_RAW_EVENTS, build_activity_history
from app.services.honeypot_status import is_online, offline_cutoff
from app.services.opencanary_logtypes import localized_logtype_label
from app.web.templating import t, templates

router = APIRouter()

_RECENT_EVENTS_LIMIT = 20


def _event_company_filter(company_ids: set[uuid.UUID]) -> ColumnElement[bool]:
    return HoneypotEvent.honeypot.has(Honeypot.companies.any(Company.id.in_(company_ids)))


async def _build_dashboard_context(
    request: Request, db: AsyncSession, user: User
) -> dict[str, object]:
    company_ids = visible_company_ids(user)
    settings_row = await get_or_create_app_settings(db)

    honeypot_query = select(Honeypot)
    if company_ids is not None:
        honeypot_query = honeypot_query.where(Honeypot.companies.any(Company.id.in_(company_ids)))
    honeypots = (await db.execute(honeypot_query)).scalars().all()

    offline_after = offline_cutoff()
    online_count = sum(1 for h in honeypots if is_online(h.last_seen_at, cutoff=offline_after))
    honeypot_stats = {
        "total": len(honeypots),
        "online": online_count,
        "offline": len(honeypots) - online_count,
    }

    now = datetime.now(UTC)
    event_query = select(func.count()).select_from(HoneypotEvent)
    if company_ids is not None:
        event_query = event_query.where(_event_company_filter(company_ids))
    last_24h = (
        await db.execute(event_query.where(HoneypotEvent.occurred_at >= now - timedelta(days=1)))
    ).scalar_one()
    last_7d = (
        await db.execute(event_query.where(HoneypotEvent.occurred_at >= now - timedelta(days=7)))
    ).scalar_one()
    event_stats = {"last_24h": last_24h, "last_7d": last_7d}

    recent_query = (
        select(HoneypotEvent)
        .options(selectinload(HoneypotEvent.honeypot))
        .order_by(HoneypotEvent.occurred_at.desc())
        .limit(_RECENT_EVENTS_LIMIT)
    )
    if company_ids is not None:
        recent_query = recent_query.where(_event_company_filter(company_ids))
    recent_events = (await db.execute(recent_query)).scalars().all()

    # Fleet-wide (or, for a company-scoped account, its own companies')
    # "what kind of activity" breakdown — the same per-type bucketing the
    # honeypot Activity tab uses (`app.services.canary_activity_history`),
    # just fed events across every honeypot in scope instead of one.
    # Capped at `MAX_RAW_EVENTS`, same reasoning as that module's own cap:
    # a 24h window is normally small, but a sustained flood (portscan)
    # across many honeypots at once could still be a lot of rows.
    activity_window_query = (
        select(HoneypotEvent)
        .where(HoneypotEvent.occurred_at >= now - timedelta(days=1))
        .order_by(HoneypotEvent.occurred_at)
        .limit(MAX_RAW_EVENTS)
    )
    if company_ids is not None:
        activity_window_query = activity_window_query.where(_event_company_filter(company_ids))
    activity_events = (await db.execute(activity_window_query)).scalars().all()
    activity = build_activity_history(
        list(activity_events),
        "24h",
        now=now,
        label_of=lambda logtype: localized_logtype_label(lambda key: t(request, key), logtype),
        other_label=t(request, "dashboard.activity_other"),
    )

    company_count = None
    company_breakdown = None
    show_breakdown = user.is_superadmin or (company_ids is not None and len(company_ids) > 1)
    if show_breakdown:
        companies_query = select(Company)
        if company_ids is not None:
            companies_query = companies_query.where(Company.id.in_(company_ids))
        companies = (await db.execute(companies_query)).scalars().all()
        company_count = len(companies)
        company_breakdown = []
        for company in companies:
            company_honeypots = [h for h in honeypots if company in h.companies]
            company_online = sum(
                1 for h in company_honeypots if is_online(h.last_seen_at, cutoff=offline_after)
            )
            events_24h = (
                await db.execute(
                    select(func.count())
                    .select_from(HoneypotEvent)
                    .where(
                        _event_company_filter({company.id}),
                        HoneypotEvent.occurred_at >= now - timedelta(days=1),
                    )
                )
            ).scalar_one()
            company_breakdown.append(
                {
                    "company_id": company.id,
                    "company_name": company.name,
                    "honeypot_count": len(company_honeypots),
                    "online_count": company_online,
                    "events_24h": events_24h,
                }
            )

    snapshot_query = select(CompanySnapshot).order_by(CompanySnapshot.snapshot_date)
    if company_ids is not None:
        snapshot_query = snapshot_query.where(CompanySnapshot.company_id.in_(company_ids))
    daily_snapshots = (await db.execute(snapshot_query)).scalars().all()

    return {
        # base.html normally sets this itself (`{% set current_user =
        # request.state.user %}`) for a full page render, but the panel
        # route below renders this same content standalone, without
        # extending base.html at all — pass it explicitly so both call
        # sites work.
        "current_user": user,
        "honeypot_stats": honeypot_stats,
        "event_stats": event_stats,
        "recent_events": recent_events,
        "company_count": company_count,
        "company_breakdown": company_breakdown,
        "daily_snapshots": daily_snapshots,
        "dashboard_trends_retention_days": settings_row.dashboard_trends_retention_days,
        "activity": activity,
    }


@router.get("/dashboard")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> object:
    context = await _build_dashboard_context(request, db, user)
    return templates.TemplateResponse(request, "dashboard/index.html", context)


@router.get("/dashboard/panel")
async def dashboard_panel(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> object:
    """The live-refreshed content div's own fetch target (see
    dashboard/index.html) — a plain re-read of whatever's currently in the
    DB, no different from the full page's own query, just rendering the
    inner partial alone."""
    context = await _build_dashboard_context(request, db, user)
    return templates.TemplateResponse(request, "partials/_dashboard_content.html", context)
