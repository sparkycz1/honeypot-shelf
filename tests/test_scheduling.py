"""Scheduled tasks — company scoping (every schedule belongs to exactly one
company via `owner_company_id`) and the basic create/run-now/delete flow."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import AccessLevel
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
        client, is_superadmin=False, company_id=company_a.id, access_level=AccessLevel.READ
    )
    response = await client.get("/scheduling")
    assert response.status_code == 200
    assert "Acme sweep" in response.text
    assert "Beta sweep" not in response.text
