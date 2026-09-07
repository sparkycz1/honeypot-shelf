"""Background job bodies — Celery Beat's three daily sweeps (see
`app.tasks.celery_app.celery_app.conf.beat_schedule`).

Same async-body/sync-wrapper split as debcontrol: each job is `async def
_do_thing(...)` (the real work, called directly by tests) plus a one-line
`def do_thing(...): return asyncio.run(_do_thing(...))` wrapped in
`@celery_app.task`. Every body opens its session as
`db_session.AsyncSessionLocal()` through the module, never a
`from app.db.session import AsyncSessionLocal` binding — see
`app.tasks.celery_app`'s fork-safety note for why that matters.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select

from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.db import session as db_session
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.services.honeypot_status import offline_cutoff
from app.tasks.celery_app import celery_app


async def _purge_old_events() -> int:
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.event_retention_days)
    async with db_session.AsyncSessionLocal() as db:
        result = await db.execute(delete(HoneypotEvent).where(HoneypotEvent.occurred_at < cutoff))
        await db.commit()
        return result.rowcount or 0


@celery_app.task(name="app.tasks.jobs.purge_old_events")
def purge_old_events() -> int:
    return asyncio.run(_purge_old_events())


async def _purge_old_audit_log_entries() -> int:
    async with db_session.AsyncSessionLocal() as db:
        app_settings = await get_or_create_app_settings(db)
        if app_settings.audit_log_retention_days is None:
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=app_settings.audit_log_retention_days)
        result = await db.execute(delete(AuditLogEntry).where(AuditLogEntry.created_at < cutoff))
        await db.commit()
        return result.rowcount or 0


@celery_app.task(name="app.tasks.jobs.purge_old_audit_log_entries")
def purge_old_audit_log_entries() -> int:
    return asyncio.run(_purge_old_audit_log_entries())


async def _record_company_snapshots() -> int:
    """One `CompanySnapshot` row per company for "yesterday" (UTC) — see
    that model's docstring. Also purges snapshots past
    `AppSettings.dashboard_trends_retention_days`."""
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date()
    cutoff = offline_cutoff()
    async with db_session.AsyncSessionLocal() as db:
        companies = (await db.execute(select(Company))).scalars().all()
        for company in companies:
            honeypots = (
                await db.execute(select(Honeypot).where(Honeypot.company_id == company.id))
            ).scalars().all()
            online = sum(1 for h in honeypots if h.last_seen_at and h.last_seen_at >= cutoff)
            event_count = (
                await db.execute(
                    select(func.count())
                    .select_from(HoneypotEvent)
                    .where(
                        HoneypotEvent.company_id == company.id,
                        func.date(HoneypotEvent.occurred_at) == yesterday,
                    )
                )
            ).scalar_one()
            existing = await db.execute(
                select(CompanySnapshot).where(
                    CompanySnapshot.company_id == company.id,
                    CompanySnapshot.snapshot_date == yesterday,
                )
            )
            row = existing.scalar_one_or_none()
            if row is None:
                row = CompanySnapshot(company_id=company.id, snapshot_date=yesterday)
                db.add(row)
            row.honeypot_count = len(honeypots)
            row.honeypots_online = online
            row.event_count = event_count

        app_settings = await get_or_create_app_settings(db)
        if app_settings.dashboard_trends_retention_days is not None:
            purge_before = yesterday - timedelta(days=app_settings.dashboard_trends_retention_days)
            await db.execute(
                delete(CompanySnapshot).where(CompanySnapshot.snapshot_date < purge_before)
            )
        await db.commit()
        return len(companies)


@celery_app.task(name="app.tasks.jobs.record_company_snapshots")
def record_company_snapshots() -> int:
    return asyncio.run(_record_company_snapshots())
