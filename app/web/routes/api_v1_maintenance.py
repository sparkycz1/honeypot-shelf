"""REST API for maintenance windows — mirrors `app/web/routes/maintenance.py`.

Same rules as the web pages: write access to a window's company
(`has_company_access(..., write=True)`) to see, create, change, end or
delete it, a window outside that scope is a 404, and the same schema
(`MaintenanceWindowSave`) and service (`app.services.maintenance_windows`)
do the work. Times are ISO 8601; a value without an offset is taken as
UTC.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_write
from app.auth.scope import has_company_access
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.maintenance_window import MaintenanceWindowSave
from app.services.maintenance_windows import apply_window_data, window_state, window_summary

router = APIRouter(prefix="/api/v1/maintenance-windows")
_manage = Depends(require_api_write)


def _window_to_dict(window: MaintenanceWindow) -> dict[str, object]:
    return {
        "id": str(window.id),
        "owner_company_id": str(window.owner_company_id),
        "name": window.name,
        "reason": window.reason,
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "state": window_state(window),
        "all_honeypots": window.all_honeypots,
        "honeypot_ids": [str(h.id) for h in window.honeypots],
        "pause_scheduled_tasks": window.pause_scheduled_tasks,
        "mute_alerts": window.mute_alerts,
        "created_by": window.created_by,
    }


async def _get_window_or_404(
    window_id: uuid.UUID, db: AsyncSession, user: User
) -> MaintenanceWindow:
    window = await db.get(MaintenanceWindow, window_id)
    if window is None or not has_company_access(user, window.owner_company_id, write=True):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Maintenance window not found.")
    return window


def _ensure_company(user: User, payload: MaintenanceWindowSave) -> None:
    if not has_company_access(user, payload.owner_company_id, write=True):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Company not found.")


def _details(window: MaintenanceWindow) -> dict[str, object]:
    return {
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "scope": window_summary(window),
        "pause_scheduled_tasks": window.pause_scheduled_tasks,
        "mute_alerts": window.mute_alerts,
    }


@router.get("", dependencies=[_manage])
async def list_maintenance_windows_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, object]]:
    """Every window this token may manage, newest start first, with its
    `state` (`active`, `upcoming` or `ended`)."""
    result = await db.execute(
        select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at.desc())
    )
    return [
        _window_to_dict(w)
        for w in result.scalars()
        if has_company_access(user, w.owner_company_id, write=True)
    ]


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_maintenance_window_api(
    request: Request,
    payload: MaintenanceWindowSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    _ensure_company(user, payload)
    window = MaintenanceWindow(created_by=user.username)
    await apply_window_data(db, window, payload)
    db.add(window)
    await db.commit()
    await db.refresh(window, ["owner_company", "honeypots"])
    await log_event(
        db,
        request=request,
        action="maintenance_window.create",
        summary=f'Scheduled maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details=_details(window),
    )
    return _window_to_dict(window)


@router.get("/{window_id}", dependencies=[_manage])
async def get_maintenance_window_api(
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _window_to_dict(await _get_window_or_404(window_id, db, user))


@router.put("/{window_id}", dependencies=[_manage])
async def update_maintenance_window_api(
    request: Request,
    window_id: uuid.UUID,
    payload: MaintenanceWindowSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    window = await _get_window_or_404(window_id, db, user)
    _ensure_company(user, payload)
    await apply_window_data(db, window, payload)
    await db.commit()
    await db.refresh(window, ["owner_company", "honeypots"])
    await log_event(
        db,
        request=request,
        action="maintenance_window.update",
        summary=f'Updated maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details=_details(window),
    )
    return _window_to_dict(window)


@router.post("/{window_id}/end", dependencies=[_manage])
async def end_maintenance_window_api(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """End an active window now (or cancel an upcoming one); it stays listed
    as ended. A window that already ended is returned unchanged."""
    window = await _get_window_or_404(window_id, db, user)
    now = datetime.now(UTC)
    if window_state(window, now) != "ended":
        if window_state(window, now) == "upcoming":
            window.starts_at = now
        window.ends_at = now
        await db.commit()
        await log_event(
            db,
            request=request,
            action="maintenance_window.end",
            summary=f'Ended maintenance window "{window.name}" early',
            target_type="maintenance_window",
            target_id=window.id,
            target_label=window.name,
        )
    return _window_to_dict(window)


@router.delete("/{window_id}", dependencies=[_manage], status_code=status.HTTP_204_NO_CONTENT)
async def delete_maintenance_window_api(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    window = await _get_window_or_404(window_id, db, user)
    name = window.name
    await db.delete(window)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.delete",
        summary=f'Deleted maintenance window "{name}"',
        target_type="maintenance_window",
        target_id=window_id,
        target_label=name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
