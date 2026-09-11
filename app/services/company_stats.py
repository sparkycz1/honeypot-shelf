"""Per-company SSH-management-plane honeypot counts — the exact queries the
Dashboard shows live (`app.web.routes.dashboard`), factored out so the
daily snapshot job (`app.tasks.jobs.record_company_snapshots`) records
precisely the same definitions rather than a second, potentially-drifting
copy of them. Direct port of debcontrol's `app.services.fleet_stats`,
scoped to one company instead of the whole (single-tenant) fleet.

`company_id=None` means no scoping at all — every honeypot in every
company (a superadmin's fleet-wide dashboard view).
"""

from __future__ import annotations

import uuid
from typing import TypedDict

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot


class CompanyStats(TypedDict):
    total: int
    reachable: int
    unreachable: int
    needs_updates: int
    needs_security_updates: int
    needs_reboot: int


async def compute_company_stats(
    db: AsyncSession, company_id: uuid.UUID | None = None
) -> CompanyStats:
    """Every SSH-management-plane count in one place."""

    async def _count(*conditions: ColumnElement[bool]) -> int:
        query = select(func.count()).select_from(Honeypot)
        if company_id is not None:
            query = query.where(Honeypot.companies.any(Company.id == company_id))
        for condition in conditions:
            query = query.where(condition)
        return (await db.execute(query)).scalar_one()

    total = await _count()
    reachable = await _count(Honeypot.is_reachable.is_(True))
    unreachable = await _count(Honeypot.is_reachable.is_(False))
    needs_updates = await _count(
        (Honeypot.upgradable_count > 0)
        | (Honeypot.flatpak_upgradable_count > 0)
        | (Honeypot.snap_upgradable_count > 0)
    )
    needs_security_updates = await _count(Honeypot.security_upgradable_count > 0)
    needs_reboot = await _count(Honeypot.reboot_required.is_(True))
    return {
        "total": total,
        "reachable": reachable,
        "unreachable": unreachable,
        "needs_updates": needs_updates,
        "needs_security_updates": needs_security_updates,
        "needs_reboot": needs_reboot,
    }
