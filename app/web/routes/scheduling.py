"""Scheduling — run an existing action (system update, update check, reboot,
shut down, run a command, ...) against one honeypot or "All honeypots" (in
one company) on a cron expression. See `app.scheduling` for the action
registry and the background jobs that evaluate and fire these.

Every schedule belongs to exactly one company (`ScheduledTask.
owner_company_id`) — write access + company scope
(`app.auth.scope.has_company_access(..., write=True)`) gates
creating/editing/running/deleting one, the same way write access gates
everything else honeypot-related. There's no separate `extra_permission`
tier for `run_command` the way debcontrol's does (its `action.terminal` on
top of `scheduling.manage`) — this app has only one write tier, so any
account that can create a schedule at all can use every registered action,
`run_command` included.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_write
from app.auth.scope import has_company_access, honeypots_visible_to
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.honeypot import Honeypot
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.actions import all_actions, get_action
from app.scheduling.cron import compute_next_run
from app.scheduling.jobs import run_scheduled_task
from app.scheduling.targets import decode_target, encode_target, task_within_scope
from app.schemas.scheduled_task import ScheduledTaskCreate
from app.web.templating import templates

router = APIRouter(prefix="/scheduling")
_write = Depends(require_write)


async def _get_task_or_404(task_id: uuid.UUID, db: AsyncSession, user: User) -> ScheduledTask:
    """The task, or a 404 — including when it exists but belongs to a
    company outside `user`'s scope. 404 rather than 403, matching the
    honeypot and company lookups."""
    result = await db.execute(
        select(ScheduledTask)
        .options(selectinload(ScheduledTask.target_honeypot))
        .where(ScheduledTask.id == task_id)
    )
    task = result.scalar_one_or_none()
    if task is None or not task_within_scope(user, task):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled task not found."
        )
    return task


async def _get_honeypots(db: AsyncSession, user: User) -> list[Honeypot]:
    result = await db.execute(honeypots_visible_to(user).order_by(Honeypot.name))
    return list(result.scalars().all())


async def _form_context(
    db: AsyncSession, user: User, form: dict[str, str], errors: list[str]
) -> dict[str, object]:
    return {
        "actions": all_actions(),
        "honeypots": await _get_honeypots(db, user),
        # A superadmin picks the owning company explicitly for an
        # ALL_HONEYPOTS schedule (the form offers every company); a
        # company-scoped user has only their own, so the form doesn't
        # need to ask.
        "is_superadmin": user.is_superadmin,
        "own_company_id": user.company_id,
        "form": form,
        "errors": errors,
    }


def _action_params_from_form(action_key: str, raw_form: dict[str, str]) -> dict[str, str]:
    """Only pull the params the selected action actually declares — anything
    else submitted is ignored rather than stored verbatim."""
    action = get_action(action_key)
    if action is None:
        return {}
    return {
        param.key: raw_form.get(f"param_{param.key}", param.default) for param in action.params
    }


def _resolve_owner_company_id(
    user: User, target_honeypot: Honeypot | None, raw_form: dict[str, str]
) -> uuid.UUID | None:
    """The company a new/edited schedule belongs to: a honeypot-targeted
    schedule always inherits its honeypot's company (the `owner_company_id`
    form field, if any, is ignored — never trust the client to have kept
    it in sync with the honeypot picker); an ALL_HONEYPOTS schedule uses
    the submitted `owner_company_id` for a superadmin, or the current
    user's own company otherwise."""
    if target_honeypot is not None:
        return target_honeypot.company_id
    if user.is_superadmin:
        raw = raw_form.get("owner_company_id", "")
        return uuid.UUID(raw) if raw else None
    return user.company_id


@router.get("")
async def list_scheduled_tasks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_honeypot), selectinload(ScheduledTask.owner_company)
        )
        .order_by(ScheduledTask.name)
    )
    tasks = [task for task in result.scalars().all() if task_within_scope(current_user, task)]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/list.html",
        {
            "tasks": tasks,
            "action_labels": {action.key: action.label for action in all_actions()},
            "csrf_token": csrf_token,
            # One-time notice after "Run now" — not persisted, just echoed
            # back from the query string.
            "ran": request.query_params.get("ran"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/new", dependencies=[_write])
async def new_scheduled_task_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    # New schedules default to enabled — everywhere else, "is_enabled" only
    # ends up in `form` when a checkbox was actually submitted (unchecked =
    # the key is simply absent from the POST body), so this default is only
    # applied here, not silently reapplied on a failed-validation re-render.
    context = await _form_context(db, current_user, {"is_enabled": "on"}, [])
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, "scheduling/new.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def _load_target_honeypot(
    db: AsyncSession, target_honeypot_id: uuid.UUID | None
) -> Honeypot | None:
    if target_honeypot_id is None:
        return None
    return await db.get(Honeypot, target_honeypot_id)


@router.post("", dependencies=[_write, Depends(verify_csrf)])
async def create_scheduled_task(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    raw_form = {key: str(value) for key, value in (await request.form()).items()}

    errors: list[str] = []
    payload: ScheduledTaskCreate | None = None
    try:
        target_type, target_honeypot_id = decode_target(raw_form.get("target", ""))
        target_honeypot = await _load_target_honeypot(db, target_honeypot_id)
        owner_company_id = _resolve_owner_company_id(current_user, target_honeypot, raw_form)
        payload = ScheduledTaskCreate(
            name=raw_form.get("name", ""),
            action=raw_form.get("action", ""),
            action_params=_action_params_from_form(raw_form.get("action", ""), raw_form),
            target_type=target_type,
            target_honeypot_id=target_honeypot_id,
            owner_company_id=owner_company_id,
            cron_expression=raw_form.get("cron_expression", ""),
            is_enabled=bool(raw_form.get("is_enabled")),
        )
    except ValueError as exc:
        errors.append(str(exc))

    if payload is not None:
        # Guaranteed non-None here by ScheduledTaskCreate's own
        # model_validator (raises "Pick a company..." otherwise) — the
        # field itself stays Optional in the schema only because it's
        # resolved by this route, not submitted directly.
        assert payload.owner_company_id is not None
        if not has_company_access(current_user, payload.owner_company_id, write=True):
            errors.append("Pick a company your account has access to.")

    if errors or payload is None:
        task_name = raw_form.get("name", "")
        await log_event(
            db,
            request=request,
            action="scheduled_task.create",
            summary=f'Rejected new scheduled task "{task_name}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        context = await _form_context(db, current_user, raw_form, errors)
        context["csrf_token"] = csrf_token
        response = templates.TemplateResponse(
            request,
            "scheduling/new.html",
            context,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    task = ScheduledTask(
        name=payload.name,
        action=payload.action,
        action_params=payload.action_params,
        target_type=payload.target_type,
        target_honeypot_id=payload.target_honeypot_id,
        owner_company_id=payload.owner_company_id,
        cron_expression=payload.cron_expression,
        is_enabled=payload.is_enabled,
        next_run_at=compute_next_run(payload.cron_expression) if payload.is_enabled else None,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    await log_event(
        db,
        request=request,
        action="scheduled_task.create",
        summary=f'Created scheduled task "{task.name}" ({task.action}, {task.cron_expression})',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )

    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{task_id}/edit", dependencies=[_write])
async def edit_scheduled_task_form(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    form = {
        "name": task.name,
        "action": task.action,
        "target": encode_target(task.target_type, task.target_honeypot_id),
        "owner_company_id": str(task.owner_company_id),
        "cron_expression": task.cron_expression,
        "is_enabled": "on" if task.is_enabled else "",
        **{f"param_{k}": v for k, v in (task.action_params or {}).items()},
    }
    context = await _form_context(db, current_user, form, [])
    context["csrf_token"] = csrf_token
    context["task"] = task
    response = templates.TemplateResponse(request, "scheduling/edit.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{task_id}/edit", dependencies=[_write, Depends(verify_csrf)])
async def update_scheduled_task(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    raw_form = {key: str(value) for key, value in (await request.form()).items()}

    errors: list[str] = []
    payload: ScheduledTaskCreate | None = None
    try:
        target_type, target_honeypot_id = decode_target(raw_form.get("target", ""))
        target_honeypot = await _load_target_honeypot(db, target_honeypot_id)
        owner_company_id = _resolve_owner_company_id(current_user, target_honeypot, raw_form)
        payload = ScheduledTaskCreate(
            name=raw_form.get("name", ""),
            action=raw_form.get("action", ""),
            action_params=_action_params_from_form(raw_form.get("action", ""), raw_form),
            target_type=target_type,
            target_honeypot_id=target_honeypot_id,
            owner_company_id=owner_company_id,
            cron_expression=raw_form.get("cron_expression", ""),
            is_enabled=bool(raw_form.get("is_enabled")),
        )
    except ValueError as exc:
        errors.append(str(exc))

    if payload is not None:
        # Guaranteed non-None here by ScheduledTaskCreate's own
        # model_validator (raises "Pick a company..." otherwise) — the
        # field itself stays Optional in the schema only because it's
        # resolved by this route, not submitted directly.
        assert payload.owner_company_id is not None
        if not has_company_access(current_user, payload.owner_company_id, write=True):
            errors.append("Pick a company your account has access to.")

    if errors or payload is None:
        await log_event(
            db,
            request=request,
            action="scheduled_task.update",
            summary=f'Rejected update to scheduled task "{task.name}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
            target_type="scheduled_task",
            target_id=task.id,
            target_label=task.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        context = await _form_context(db, current_user, raw_form, errors)
        context["csrf_token"] = csrf_token
        context["task"] = task
        response = templates.TemplateResponse(
            request,
            "scheduling/edit.html",
            context,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    assert payload.owner_company_id is not None  # see the model_validator note above
    task.name = payload.name
    task.action = payload.action
    task.action_params = payload.action_params
    task.target_type = payload.target_type
    task.target_honeypot_id = payload.target_honeypot_id
    task.owner_company_id = payload.owner_company_id
    task.cron_expression = payload.cron_expression
    task.is_enabled = payload.is_enabled
    task.next_run_at = compute_next_run(payload.cron_expression) if payload.is_enabled else None

    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.update",
        summary=f'Updated scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{task_id}/toggle", dependencies=[_write, Depends(verify_csrf)])
async def toggle_scheduled_task(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    task.is_enabled = not task.is_enabled
    task.next_run_at = compute_next_run(task.cron_expression) if task.is_enabled else None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.enable" if task.is_enabled else "scheduled_task.disable",
        summary=f'{"Enabled" if task.is_enabled else "Disabled"} scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{task_id}/run-now", dependencies=[_write, Depends(verify_csrf)])
async def run_scheduled_task_now(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Enqueue an immediate, one-off run — same job the per-minute
    scheduler tick would enqueue, useful for verifying a new schedule
    without waiting for its cron expression to come due. Doesn't affect
    `next_run_at`."""
    task = await _get_task_or_404(task_id, db, current_user)
    run_scheduled_task.delay(str(task.id))
    await log_event(
        db,
        request=request,
        action="scheduled_task.run_now",
        summary=f'Manually ran scheduled task "{task.name}" now',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return RedirectResponse(
        url=f"/scheduling?ran={task.id}", status_code=status.HTTP_303_SEE_OTHER
    )


# How many past runs the history page shows — a debugging aid for a
# schedule that's misbehaving, not an unbounded audit trail (the audit log
# already keeps every firing forever, see `app.scheduling.jobs`).
_HISTORY_PAGE_SIZE = 50


@router.get("/{task_id}/history")
async def scheduled_task_history(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    result = await db.execute(
        select(ScheduledTaskRun)
        .where(ScheduledTaskRun.task_id == task_id)
        .order_by(ScheduledTaskRun.fired_at.desc())
        .limit(_HISTORY_PAGE_SIZE)
    )
    runs = result.scalars().all()
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/history.html",
        {"task": task, "runs": runs, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{task_id}/delete", dependencies=[_write, Depends(verify_csrf)])
async def delete_scheduled_task(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    task_name = task.name
    await db.delete(task)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.delete",
        summary=f'Deleted scheduled task "{task_name}"',
        target_type="scheduled_task",
        target_id=task_id,
        target_label=task_name,
    )
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)
