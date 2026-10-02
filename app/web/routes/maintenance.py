"""Maintenance windows (`/scheduling/maintenance`) — scheduled time ranges
during which notifications about the chosen honeypots are muted and, when
the window says so, scheduled tasks skip them. See
`app.db.models.maintenance_window` for the semantics and
`app.services.maintenance_windows` for the matching; the REST twin is
`app/web/routes/api_v1_maintenance.py`. Ported from debcontrol.

Scoped like Scheduling: every window belongs to one company, and write
access to that company (`has_company_access(..., write=True)`) gates
seeing, creating, editing, ending and deleting it. A window outside the
account's scope is reported as missing (404), never as forbidden.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_write
from app.auth.scope import has_company_access, honeypots_visible_to
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.maintenance_window import MAX_WINDOW_DURATION, MaintenanceWindowSave
from app.services.maintenance_windows import apply_window_data, window_state, window_summary
from app.web.templating import parse_local_input, t, templates, to_local_input

router = APIRouter(prefix="/scheduling/maintenance")
_write = Depends(require_write)

# How many ended windows the list keeps showing.
_PAST_WINDOWS_SHOWN = 20


async def _get_window_or_404(
    window_id: uuid.UUID, db: AsyncSession, user: User
) -> MaintenanceWindow:
    window = await db.get(MaintenanceWindow, window_id)
    if window is None or not has_company_access(user, window.owner_company_id, write=True):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Maintenance window not found.")
    return window


async def writable_companies(db: AsyncSession, user: User) -> list[Company]:
    """The companies `user` may schedule a window for."""
    companies = (await db.execute(select(Company).order_by(Company.name))).scalars().all()
    return [c for c in companies if has_company_access(user, c.id, write=True)]


async def _form_page(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    window: MaintenanceWindow | None,
    form: dict[str, Any],
    errors: list[str],
) -> Response:
    companies = await writable_companies(db, user)
    honeypots = [
        h
        for h in (await db.execute(honeypots_visible_to(user).order_by(Honeypot.name))).scalars()
        if any(has_company_access(user, c.id, write=True) for c in h.companies)
    ]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/maintenance_form.html",
        {
            "window": window,
            "form": form,
            "errors": errors,
            "companies": companies,
            "honeypots": honeypots,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _form_of(window: MaintenanceWindow) -> dict[str, Any]:
    return {
        "owner_company_id": str(window.owner_company_id),
        "name": window.name,
        "reason": window.reason or "",
        "starts_at": to_local_input(window.starts_at),
        "ends_at": to_local_input(window.ends_at),
        "all_honeypots": window.all_honeypots,
        "honeypot_ids": [str(h.id) for h in window.honeypots],
        "pause_scheduled_tasks": window.pause_scheduled_tasks,
        "mute_alerts": window.mute_alerts,
    }


async def _parse_form(
    request: Request, user: User
) -> tuple[dict[str, Any], MaintenanceWindowSave | None, str]:
    raw = await request.form()
    form: dict[str, Any] = {
        "owner_company_id": str(raw.get("owner_company_id", "")),
        "name": str(raw.get("name", "")),
        "reason": str(raw.get("reason", "")),
        "starts_at": str(raw.get("starts_at", "")),
        "ends_at": str(raw.get("ends_at", "")),
        "all_honeypots": bool(raw.get("all_honeypots")),
        "honeypot_ids": [str(v) for v in raw.getlist("honeypot_ids")],
        "pause_scheduled_tasks": bool(raw.get("pause_scheduled_tasks")),
        "mute_alerts": bool(raw.get("mute_alerts")),
    }
    try:
        owner_company_id = uuid.UUID(form["owner_company_id"])
    except ValueError:
        return form, None, t(request, "maintenance.error.company")
    if not has_company_access(user, owner_company_id, write=True):
        return form, None, t(request, "maintenance.error.company")
    try:
        starts_at = parse_local_input(form["starts_at"])
        ends_at = parse_local_input(form["ends_at"])
    except ValueError:
        return form, None, t(request, "maintenance.error.dates")
    # The schema enforces the same rules; checked here first only to word
    # the common mistakes in the viewer's language.
    if not form["name"].strip():
        return form, None, t(request, "maintenance.error.name")
    if ends_at <= starts_at:
        return form, None, t(request, "maintenance.error.order")
    if ends_at - starts_at > MAX_WINDOW_DURATION:
        return form, None, t(request, "maintenance.error.too_long")
    if not (form["all_honeypots"] or form["honeypot_ids"]):
        return form, None, t(request, "maintenance.error.scope")
    try:
        payload = MaintenanceWindowSave(
            owner_company_id=owner_company_id,
            name=form["name"],
            reason=form["reason"],
            starts_at=starts_at,
            ends_at=ends_at,
            all_honeypots=form["all_honeypots"],
            honeypot_ids=form["honeypot_ids"],
            pause_scheduled_tasks=form["pause_scheduled_tasks"],
            mute_alerts=form["mute_alerts"],
        )
    except ValidationError as exc:
        message = str(exc.errors()[0].get("msg", "")).removeprefix("Value error, ")
        return form, None, message
    return form, payload, ""


def _audit_details(window: MaintenanceWindow) -> dict[str, object]:
    return {
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "scope": window_summary(window),
        "pause_scheduled_tasks": window.pause_scheduled_tasks,
        "mute_alerts": window.mute_alerts,
    }


def _back() -> RedirectResponse:
    return RedirectResponse(url="/scheduling/maintenance", status_code=status.HTTP_303_SEE_OTHER)


@router.get("", dependencies=[_write])
async def list_windows(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    now = datetime.now(UTC)
    windows = [
        w
        for w in (
            await db.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at))
        ).scalars()
        if has_company_access(current_user, w.owner_company_id, write=True)
    ]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/maintenance.html",
        {
            "active": [w for w in windows if window_state(w, now) == "active"],
            "upcoming": [w for w in windows if window_state(w, now) == "upcoming"],
            "ended": [w for w in windows if window_state(w, now) == "ended"][-_PAST_WINDOWS_SHOWN:][
                ::-1
            ],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/new", dependencies=[_write])
async def new_window_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    companies = await writable_companies(db, current_user)
    return await _form_page(
        request,
        db,
        current_user,
        window=None,
        form={
            "owner_company_id": str(companies[0].id) if len(companies) == 1 else "",
            "starts_at": to_local_input(now),
            "pause_scheduled_tasks": True,
            "honeypot_ids": [],
        },
        errors=[],
    )


@router.post("", dependencies=[_write, Depends(verify_csrf)])
async def create_window(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    form, payload, error = await _parse_form(request, current_user)
    if payload is None:
        return await _form_page(request, db, current_user, window=None, form=form, errors=[error])
    window = MaintenanceWindow(created_by=current_user.username)
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
        details=_audit_details(window),
    )
    return _back()


@router.get("/{window_id}/edit", dependencies=[_write])
async def edit_window_form(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    window = await _get_window_or_404(window_id, db, current_user)
    return await _form_page(
        request, db, current_user, window=window, form=_form_of(window), errors=[]
    )


@router.post("/{window_id}/edit", dependencies=[_write, Depends(verify_csrf)])
async def update_window(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    window = await _get_window_or_404(window_id, db, current_user)
    form, payload, error = await _parse_form(request, current_user)
    if payload is None:
        return await _form_page(request, db, current_user, window=window, form=form, errors=[error])
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
        details=_audit_details(window),
    )
    return _back()


@router.post("/{window_id}/end", dependencies=[_write, Depends(verify_csrf)])
async def end_window_now(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Finish an active window early (or cancel an upcoming one) — kept in
    the list as ended, rather than deleted, so it's still visible what was
    muted and when."""
    window = await _get_window_or_404(window_id, db, current_user)
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
    return _back()


@router.post("/{window_id}/delete", dependencies=[_write, Depends(verify_csrf)])
async def delete_window(
    request: Request,
    window_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    window = await _get_window_or_404(window_id, db, current_user)
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
    return _back()
