"""Settings — superadmin-only. Currently read-only display of
`AppSettings`; the edit forms (LDAP/OIDC config, retention policy, syslog
forwarding) mirror debcontrol's Settings page tab-for-tab but aren't built
yet — see CLAUDE.md."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_superadmin
from app.core.app_settings import get_or_create_app_settings
from app.core.version import APP_VERSION
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter(prefix="/settings", dependencies=[Depends(require_superadmin)])


@router.get("")
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)) -> object:
    settings_row = await get_or_create_app_settings(db)
    return templates.TemplateResponse(
        request,
        "settings/index.html",
        {"settings_row": settings_row, "app_version": APP_VERSION},
    )
