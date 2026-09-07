"""User management — superadmin-only. List is real; create/edit forms are
deliberately not built yet (see CLAUDE.md's open questions: self-service
invites vs. superadmin-only creation, and whether a company's own
`READ_WRITE` user should be able to manage users within their own
company). `scripts/create_admin.py` is the bootstrap path for the very
first account in a fresh deployment.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import require_superadmin
from app.db.models.user import User
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter(prefix="/users", dependencies=[Depends(require_superadmin)])


@router.get("")
async def list_users(request: Request, db: AsyncSession = Depends(get_db)) -> object:
    users = (
        await db.execute(
            select(User).options(selectinload(User.company)).order_by(User.username)
        )
    ).scalars().all()
    return templates.TemplateResponse(request, "users/list.html", {"users": users})
