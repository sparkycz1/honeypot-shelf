"""Companies (tenants) — superadmin-only for now (see CLAUDE.md's open
questions: whether a company's own `READ_WRITE` users should ever manage
their own company's profile). List + detail only; create/edit/delete are
still to be built once that's answered.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_superadmin
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.db.session import get_db
from app.services.honeypot_status import offline_cutoff
from app.web.templating import templates

router = APIRouter(prefix="/companies", dependencies=[Depends(require_superadmin)])


@router.get("")
async def list_companies(request: Request, db: AsyncSession = Depends(get_db)) -> object:
    companies = (await db.execute(select(Company).order_by(Company.name))).scalars().all()
    cutoff = offline_cutoff()
    rows = []
    for company in companies:
        honeypots = (
            await db.execute(select(Honeypot).where(Honeypot.company_id == company.id))
        ).scalars().all()
        user_count = (
            await db.execute(
                select(func.count()).select_from(User).where(User.company_id == company.id)
            )
        ).scalar_one()
        rows.append(
            {
                "company": company,
                "honeypot_count": len(honeypots),
                "online_count": sum(1 for h in honeypots if h.last_seen_at and h.last_seen_at >= cutoff),
                "user_count": user_count,
            }
        )
    return templates.TemplateResponse(request, "companies/list.html", {"rows": rows})


@router.get("/{company_id}")
async def company_detail(
    company_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)
) -> object:
    company = await db.get(Company, company_id)
    if company is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found.")
    honeypots = (
        await db.execute(select(Honeypot).where(Honeypot.company_id == company.id))
    ).scalars().all()
    users = (
        await db.execute(select(User).where(User.company_id == company.id))
    ).scalars().all()
    return templates.TemplateResponse(
        request, "companies/detail.html", {"company": company, "honeypots": honeypots, "users": users}
    )
