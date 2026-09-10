"""Scheduled tasks — company scoping (every schedule belongs to exactly one
company via `owner_company_id`) and the basic create/run-now/delete flow."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db import session as db_session_module
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun, ScheduledTaskRunOutcome
from app.db.models.user import AccessLevel
from app.scheduling.jobs import _run_scheduled_task
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_create_all_honeypots_schedule(client, db_session_factory):
    company = await create_company(db_session_factory)
    new_form = await client.get("/scheduling/new")
    response = await client.post(
        "/scheduling",
        data={
            "name": "Nightly check",
            "action": "check_updates",
            "target": "all",
            "owner_company_id": str(company.id),
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": _csrf_from(new_form),
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        result = await db.execute(select(ScheduledTask))
        tasks = result.scalars().all()
        assert len(tasks) == 1
        assert tasks[0].owner_company_id == company.id


async def test_company_user_only_sees_own_companys_schedules(
    client, db_session_factory, login_as
):
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    async with db_session_factory() as db:
        db.add(
            ScheduledTask(
                name="Acme sweep",
                action="check_updates",
                target_type="all_honeypots",
                owner_company_id=company_a.id,
                cron_expression="0 3 * * *",
            )
        )
        db.add(
            ScheduledTask(
                name="Beta sweep",
                action="check_updates",
                target_type="all_honeypots",
                owner_company_id=company_b.id,
                cron_expression="0 3 * * *",
            )
        )
        await db.commit()

    await login_as(
        client, is_superadmin=False, company_id=company_a.id, access_level=AccessLevel.READ_WRITE
    )
    response = await client.get("/scheduling")
    assert response.status_code == 200
    assert "Acme sweep" in response.text
    assert "Beta sweep" not in response.text


async def test_read_only_user_cannot_reach_scheduling(client, db_session_factory, login_as):
    """Scheduling is a write-tier feature end to end now — a read-only
    account gets 403, not a read-only view of it (the nav link is hidden
    for the same reason)."""
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/scheduling")
    assert response.status_code == 403


async def test_run_records_history_and_history_page_offers_retry(
    client, db_session_factory, monkeypatch
):
    """`_run_scheduled_task` (the Celery job body) writes one
    `ScheduledTaskRun` row per firing — success and failure alike — so a
    misbehaving schedule can be diagnosed after the fact. See
    `ScheduledTaskRun`'s module docstring."""
    monkeypatch.setattr(db_session_module, "AsyncSessionLocal", db_session_factory)

    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        task = ScheduledTask(
            name="Nightly sweep",
            action="check_updates",
            target_type="all_honeypots",
            owner_company_id=company.id,
            cron_expression="0 3 * * *",
        )
        db.add(task)
        await db.commit()
        await db.refresh(task)
        task_id = task.id

    # A successful firing (no honeypots in the company — 0 attempted, 0
    # skipped — is still a successful dispatch, not a failure).
    result = await _run_scheduled_task(str(task_id))
    assert result["ok"] is True

    # An unknown action — the same "misconfigured schedule" case the web
    # route already handles for `get_action(...) is None`.
    async with db_session_factory() as db:
        broken = ScheduledTask(
            name="Broken",
            action="does_not_exist",
            target_type="all_honeypots",
            owner_company_id=company.id,
            cron_expression="0 3 * * *",
        )
        db.add(broken)
        await db.commit()
        await db.refresh(broken)
        broken_id = broken.id
    broken_result = await _run_scheduled_task(str(broken_id))
    assert broken_result["ok"] is False

    async with db_session_factory() as db:
        runs = (
            (await db.execute(select(ScheduledTaskRun).where(ScheduledTaskRun.task_id == task_id)))
            .scalars()
            .all()
        )
        assert len(runs) == 1
        assert runs[0].outcome == ScheduledTaskRunOutcome.SUCCESS

        broken_runs = (
            (
                await db.execute(
                    select(ScheduledTaskRun).where(ScheduledTaskRun.task_id == broken_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(broken_runs) == 1
        assert broken_runs[0].outcome == ScheduledTaskRunOutcome.FAILURE

    history = await client.get(f"/scheduling/{task_id}/history")
    assert history.status_code == 200
    assert "Nightly sweep" in history.text

    broken_history = await client.get(f"/scheduling/{broken_id}/history")
    assert broken_history.status_code == 200
    # A failed run offers a "Retry now" button — the existing "run-now" POST.
    assert f'/scheduling/{broken_id}/run-now' in broken_history.text
