"""REST API for the Dashboard's trend snapshots — the raw daily series
behind the Dashboard's SVG chart, for anyone who wants to graph it
externally (Grafana, a spreadsheet, ...). Read-only.

Unlike debcontrol's single fleet-wide `FleetSnapshot`, this app's
`CompanySnapshot` is per-company — a superadmin sees every company's
series; a company-scoped account only ever sees its own, scoped the same
way `honeypots_visible_to`/`companies_visible_to` scope everything else
(see `app.auth.scope`).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user
from app.auth.scope import visible_company_id
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.user import User
from app.db.session import get_db

router = APIRouter(prefix="/api/v1/dashboard")

_view = Depends(get_api_token_user)


def _snapshot_to_dict(snapshot: CompanySnapshot) -> dict[str, object]:
    return {
        "company_id": str(snapshot.company_id),
        "date": snapshot.snapshot_date.isoformat(),
        "honeypot_count": snapshot.honeypot_count,
        "honeypots_online": snapshot.honeypots_online,
        "event_count": snapshot.event_count,
        "honeypots_reachable": snapshot.honeypots_reachable,
        "needs_updates": snapshot.needs_updates,
        "needs_security_updates": snapshot.needs_security_updates,
        "needs_reboot": snapshot.needs_reboot,
    }


@router.get("/trends", dependencies=[_view])
async def dashboard_trends_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Every retained daily snapshot, oldest first, for every company this
    account can see — whatever the retention purge
    (`app.tasks.jobs.purge_old_company_snapshots`) has left in the table,
    with no further filtering here (mirrors the web Dashboard)."""
    query = select(CompanySnapshot).order_by(CompanySnapshot.snapshot_date.asc())
    company_id = visible_company_id(user)
    if company_id is not None:
        query = query.where(CompanySnapshot.company_id == company_id)
    result = await db.execute(query)
    snapshots = list(result.scalars().all())
    return {"snapshots": [_snapshot_to_dict(s) for s in snapshots]}
