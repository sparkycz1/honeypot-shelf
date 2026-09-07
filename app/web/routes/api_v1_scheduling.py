"""REST API for scheduled tasks — mirrors `app/web/routes/scheduling.py`.

See `app.web.routes.api_v1`'s module docstring for the general design
(same write/company-scope rules as the equivalent web route, same
underlying service calls, mounted under the same `/api/v1` prefix).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_write
from app.auth.scope import has_company_access
from app.db.models.honeypot import Honeypot
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.cron import compute_next_run
from app.scheduling.jobs import run_scheduled_task
from app.scheduling.targets import task_within_scope
from app.schemas.scheduled_task import ScheduledTaskCreate

router = APIRouter(prefix="/api/v1/scheduling")

_view = Depends(get_api_token_user)
_manage = Depends(require_api_write)


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _task_to_dict(task: ScheduledTask) -> dict[str, object]:
    return {
        "id": str(task.id),
        "name": task.name,
        "action": task.action,
        "action_params": task.action_params,
        "target_type": task.target_type.value,
        "target_honeypot_id": str(task.target_honeypot_id) if task.target_honeypot_id else None,
        "owner_company_id": str(task.owner_company_id),
        "cron_expression": task.cron_expression,
        "is_enabled": task.is_enabled,
        "next_run_at": _isoformat(task.next_run_at),
        "last_run_at": _isoformat(task.last_run_at),
        "last_run_summary": task.last_run_summary,
    }


async def _get_task_or_404(task_id: uuid.UUID, db: AsyncSession, user: User) -> ScheduledTask:
    """Scoped like the web UI's equivalent: a task owned by a company
    outside this account's scope is a 404 here too. See
    `app/web/routes/scheduling.py`."""
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


async def _resolve_owner_company_id(
    db: AsyncSession, user: User, payload: ScheduledTaskCreate
) -> uuid.UUID:
    """The company a schedule belongs to: a honeypot-targeted schedule
    always inherits its honeypot's company (`payload.owner_company_id` is
    ignored — never trust the client to have kept it in sync with the
    honeypot); an ALL_HONEYPOTS schedule uses `payload.owner_company_id`
    as submitted."""
    if payload.target_honeypot_id is not None:
        honeypot = await db.get(Honeypot, payload.target_honeypot_id)
        if honeypot is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown honeypot.")
        return honeypot.company_id
    return payload.owner_company_id


async def _require_target_in_scope(
    db: AsyncSession, user: User, payload: ScheduledTaskCreate
) -> uuid.UUID:
    """Resolves and validates the schedule's owning company — rejects a
    company this account may not write to. Enforced at create/edit time
    only: a stored schedule fires with no current user to scope to."""
    owner_company_id = await _resolve_owner_company_id(db, user, payload)
    if not has_company_access(user, owner_company_id, write=True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='"owner_company_id" must name a company this account has write access to.',
        )
    return owner_company_id


@router.get("", dependencies=[_view])
async def list_scheduled_tasks_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    result = await db.execute(select(ScheduledTask).order_by(ScheduledTask.name))
    return [_task_to_dict(t) for t in result.scalars().all() if task_within_scope(user, t)]


@router.get("/{task_id}", dependencies=[_view])
async def get_scheduled_task_api(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _task_to_dict(await _get_task_or_404(task_id, db, user))


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_scheduled_task_api(
    request: Request,
    payload: ScheduledTaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    owner_company_id = await _require_target_in_scope(db, user, payload)
    task = ScheduledTask(
        name=payload.name,
        action=payload.action,
        action_params=payload.action_params,
        target_type=payload.target_type,
        target_honeypot_id=payload.target_honeypot_id,
        owner_company_id=owner_company_id,
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
    return _task_to_dict(task)


@router.put("/{task_id}", dependencies=[_manage])
async def update_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    payload: ScheduledTaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    owner_company_id = await _require_target_in_scope(db, user, payload)
    task.name = payload.name
    task.action = payload.action
    task.action_params = payload.action_params
    task.target_type = payload.target_type
    task.target_honeypot_id = payload.target_honeypot_id
    task.owner_company_id = owner_company_id
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
    return _task_to_dict(task)


@router.post("/{task_id}/enable", dependencies=[_manage])
async def enable_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    task.is_enabled = True
    task.next_run_at = compute_next_run(task.cron_expression)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.enable",
        summary=f'Enabled scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.post("/{task_id}/disable", dependencies=[_manage])
async def disable_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    task.is_enabled = False
    task.next_run_at = None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.disable",
        summary=f'Disabled scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.post("/{task_id}/run-now", dependencies=[_manage])
async def run_scheduled_task_now_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
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
    return {"ok": True}


@router.delete("/{task_id}", dependencies=[_manage])
async def delete_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, user)
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
    return Response(status_code=status.HTTP_204_NO_CONTENT)
