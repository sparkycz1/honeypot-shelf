"""Schedule time zones and the cron "next runs" preview — ported from
debcontrol (`app.scheduling.cron`, `ScheduledTask.timezone`)."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.core.timezones import is_valid_timezone, timezone_names
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.scheduling.cron import compute_next_run, next_runs
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


def test_a_schedule_is_read_in_its_own_zone_across_dst():
    # 03:00 Prague is 01:00 UTC in summer (CEST) and 02:00 UTC in winter (CET).
    summer = compute_next_run("0 3 * * *", datetime(2026, 7, 1, 12, tzinfo=UTC), "Europe/Prague")
    winter = compute_next_run("0 3 * * *", datetime(2026, 12, 1, 12, tzinfo=UTC), "Europe/Prague")
    assert summer == datetime(2026, 7, 2, 1, 0, tzinfo=UTC)
    assert winter == datetime(2026, 12, 2, 2, 0, tzinfo=UTC)


def test_no_zone_still_means_utc():
    after = datetime(2026, 7, 1, 12, tzinfo=UTC)
    assert compute_next_run("0 3 * * *", after) == datetime(2026, 7, 2, 3, 0, tzinfo=UTC)


def test_next_runs_lists_upcoming_times_and_rejects_garbage():
    runs = next_runs("0 */6 * * *", after=datetime(2026, 7, 1, 0, 30, tzinfo=UTC))
    assert [r.hour for r in runs] == [6, 12, 18, 0, 6]
    with pytest.raises(ValueError):
        next_runs("not cron")


def test_timezone_names_and_validation():
    assert "Europe/Prague" in timezone_names() and "UTC" in timezone_names()
    assert is_valid_timezone("Europe/Prague")
    assert not is_valid_timezone("Mars/Olympus")
    assert not is_valid_timezone("")


async def test_cron_preview_renders_runs_in_the_chosen_zone(client):
    response = await client.get(
        "/scheduling/cron-preview",
        params={"cron_expression": "0 3 * * *", "timezone": "Europe/Prague"},
    )
    assert response.status_code == 200
    assert "Next runs:" in response.text
    assert "03:00 Europe/Prague" in response.text

    bad = await client.get("/scheduling/cron-preview", params={"cron_expression": "nope"})
    assert "Not a valid cron expression yet" in bad.text


async def test_saving_a_schedule_with_a_zone(client, db_session_factory):
    company = await create_company(db_session_factory)
    form = await client.get("/scheduling/new")
    assert 'name="timezone"' in form.text
    response = await client.post(
        "/scheduling",
        data={
            "name": "Prague nightly",
            "action": "check_updates",
            "target": "all",
            "owner_company_id": str(company.id),
            "cron_expression": "0 3 * * *",
            "timezone": "Europe/Prague",
            "is_enabled": "on",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        task = (await db.execute(select(ScheduledTask))).scalar_one()
    assert task.timezone == "Europe/Prague"
    assert task.next_run_at is not None
    next_run = (
        task.next_run_at.replace(tzinfo=UTC)
        if task.next_run_at.tzinfo is None
        else task.next_run_at
    )
    assert next_run.astimezone(ZoneInfo("Europe/Prague")).hour == 3


async def test_an_unknown_zone_is_refused(client, db_session_factory):
    company = await create_company(db_session_factory)
    form = await client.get("/scheduling/new")
    response = await client.post(
        "/scheduling",
        data={
            "name": "Bad zone",
            "action": "check_updates",
            "target": "all",
            "owner_company_id": str(company.id),
            "cron_expression": "0 3 * * *",
            "timezone": "Mars/Olympus",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 422
    assert "not a known time zone" in response.text


async def test_api_cron_preview_and_timezone_field(client, db_session_factory):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        _token, raw = await create_api_token(db, user, name="t", expires_at=None)
        await db.commit()
    headers = {"Authorization": f"Bearer {raw}"}

    preview = await client.get(
        "/api/v1/scheduling/cron-preview",
        params={"cron_expression": "0 3 * * *", "timezone": "Europe/Prague"},
        headers=headers,
    )
    assert preview.status_code == 200
    assert len(preview.json()["next_runs"]) == 5
    bad = await client.get(
        "/api/v1/scheduling/cron-preview",
        params={"cron_expression": "0 3 * * *", "timezone": "Mars/Olympus"},
        headers=headers,
    )
    assert bad.status_code == 400

    created = await client.post(
        "/api/v1/scheduling",
        headers=headers,
        json={
            "name": "API Prague",
            "action": "check_updates",
            "target_type": "all_honeypots",
            "owner_company_id": str(company.id),
            "cron_expression": "0 3 * * *",
            "timezone": "Europe/Prague",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["timezone"] == "Europe/Prague"
