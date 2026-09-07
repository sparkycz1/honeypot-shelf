"""Honeypots: list (scoped to the user's own company, or every company for
a superadmin) and a detail page with its recent events.

Create/edit/delete and per-honeypot ingest-token rotation are deliberately
not built yet — see CLAUDE.md's open-questions list (who's allowed to
register a new honeypot, what identifies one, whether `READ_WRITE` users
manage their own company's honeypots or that's superadmin-only). This
route only covers the read side so the app has something real to look at.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import get_current_user
from app.auth.scope import ensure_company_access, visible_company_id
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.honeypot_status import offline_cutoff, status_of
from app.web.templating import templates

router = APIRouter()

_RECENT_EVENTS_LIMIT = 50


@router.get("/honeypots")
async def list_honeypots(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> object:
    company_id = visible_company_id(user)
    query = select(Honeypot).options(selectinload(Honeypot.company)).order_by(Honeypot.hostname)
    if company_id is not None:
        query = query.where(Honeypot.company_id == company_id)
    honeypots = (await db.execute(query)).scalars().all()

    cutoff = offline_cutoff()
    rows = [{"honeypot": h, "status": status_of(h, cutoff=cutoff)} for h in honeypots]

    return templates.TemplateResponse(
        request, "honeypots/list.html", {"rows": rows, "show_company_column": user.is_superadmin}
    )


@router.get("/honeypots/{honeypot_id}")
async def honeypot_detail(
    honeypot_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> object:
    honeypot = await db.get(Honeypot, honeypot_id, options=[selectinload(Honeypot.company)])
    if honeypot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found.")
    ensure_company_access(user, honeypot.company_id)

    events = (
        await db.execute(
            select(HoneypotEvent)
            .where(HoneypotEvent.honeypot_id == honeypot.id)
            .order_by(HoneypotEvent.occurred_at.desc())
            .limit(_RECENT_EVENTS_LIMIT)
        )
    ).scalars().all()

    return templates.TemplateResponse(
        request,
        "honeypots/detail.html",
        {"honeypot": honeypot, "status": status_of(honeypot), "events": events},
    )
