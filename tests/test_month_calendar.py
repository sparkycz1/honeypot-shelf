"""The month calendar (`app.services.month_calendar`): scheduled runs,
maintenance windows and update batches, day by day, each limited to what
the account may see."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from httpx2 import AsyncClient

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.user import User
from app.services import month_calendar
from tests.conftest import create_company


def test_month_parameter_falls_back_to_this_month() -> None:
    today = date(2026, 10, 12)

    assert month_calendar.parse_month("2026-03", today) == (2026, 3)
    for bad in ("", "2026-13", "1999-01", "2026-3", "abcd-ef", "2026-03-01"):
        assert month_calendar.parse_month(bad, today) == (2026, 10), bad


def test_a_tasks_runs_are_those_of_its_cron_in_its_zone() -> None:
    task = ScheduledTask(cron_expression="30 3 * * 1", timezone="Europe/Prague")
    start, end = datetime(2026, 3, 1, tzinfo=UTC), datetime(2026, 4, 1, tzinfo=UTC)

    runs = month_calendar.task_runs(task, start, end)

    # Mondays 03:30 Prague: 02:30 UTC in winter, 01:30 UTC after the change.
    assert [r.day for r in runs] == [2, 9, 16, 23, 30]
    assert [r.hour for r in runs] == [2, 2, 2, 2, 1]
    assert month_calendar.task_runs(ScheduledTask(cron_expression="nonsense"), start, end) == []


async def _seed(db_session_factory: Any, company_id: uuid.UUID, prefix: str) -> uuid.UUID:
    batch_id = uuid.uuid4()
    async with db_session_factory() as db:
        company = await db.get(Company, company_id)
        honeypots = [
            Honeypot(companies=[company], name=f"{prefix}-{n}", host_key_fingerprint="SHA256:x")
            for n in (1, 2)
        ]
        db.add_all(honeypots)
        db.add_all(
            [
                ScheduledTask(
                    owner_company_id=company_id,
                    name=f"{prefix} nightly updates",
                    action="system_update",
                    target_type=ScheduleTargetType.ALL_HONEYPOTS,
                    cron_expression="0 3 * * *",
                ),
                ScheduledTask(
                    owner_company_id=company_id,
                    name=f"{prefix} sampling",
                    action="force_monitoring_sample",
                    target_type=ScheduleTargetType.ALL_HONEYPOTS,
                    cron_expression="*/15 * * * *",
                    is_enabled=False,
                ),
                MaintenanceWindow(
                    owner_company_id=company_id,
                    name=f"{prefix} rack move",
                    starts_at=datetime(2026, 3, 10, 20, 0, tzinfo=UTC),
                    ends_at=datetime(2026, 3, 12, 6, 0, tzinfo=UTC),
                    all_honeypots=True,
                    pause_scheduled_tasks=True,
                ),
            ]
        )
        await db.flush()
        for honeypot, status in zip(
            honeypots, (UpdateRunStatus.SUCCEEDED, UpdateRunStatus.FAILED), strict=True
        ):
            db.add(
                HoneypotUpdateRun(
                    honeypot_id=honeypot.id,
                    strategy=UpgradeStrategy.UPGRADE,
                    status=status,
                    batch_id=batch_id,
                    created_at=datetime(2026, 3, 5, 3, 0, 5, tzinfo=UTC),
                )
            )
        await db.commit()
    return batch_id


async def test_calendar_page_and_api(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    batch_id = await _seed(db_session_factory, company.id, "acme")

    page = await client.get("/scheduling/calendar?month=2026-03")
    listing = await client.get("/scheduling")

    assert page.status_code == 200
    assert "Calendar: March 2026" in page.text
    assert 'href="/scheduling/calendar?month=2026-02"' in page.text
    assert 'href="/scheduling/calendar?month=2026-04"' in page.text
    assert f'href="/batches/{batch_id}"' in page.text
    assert "Update of 2 honeypots · 1 failed" in page.text
    assert "acme sampling" in page.text and "96 (off)" in page.text
    assert 'href="/scheduling/calendar"' in listing.text

    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    api = (
        await client.get(
            "/api/v1/scheduling/calendar?month=2026-03",
            headers={"Authorization": f"Bearer {raw}"},
        )
    ).json()
    days = {day["date"]: day["entries"] for day in api["days"]}
    assert api["month"] == "2026-03" and len(days) == 31
    fifth = days["2026-03-05"]
    assert [e["kind"] for e in fifth].count("task") == 2
    batch = next(e for e in fifth if e["kind"] == "batch")
    assert (batch["label"], batch["count"], batch["flag"]) == ("2", 1, True)
    # The window covers three days; only its first carries the start time.
    windows = {d: [e for e in days[d] if e["kind"] == "window"] for d in days}
    assert [d for d, found in windows.items() if found] == [
        "2026-03-10",
        "2026-03-11",
        "2026-03-12",
    ]
    assert windows["2026-03-10"][0]["at"] is not None and windows["2026-03-11"][0]["at"] is None
    assert windows["2026-03-10"][0]["flag"] is True


async def test_a_company_user_sees_only_their_own_company(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    mine = await create_company(db_session_factory, name="Mine")
    theirs = await create_company(db_session_factory, name="Theirs")
    own_batch = await _seed(db_session_factory, mine.id, "mine")
    other_batch = await _seed(db_session_factory, theirs.id, "theirs")
    await login_as(client, company_id=mine.id, access_level=AccessLevel.READ_WRITE)

    page = await client.get("/scheduling/calendar?month=2026-03")

    assert "mine nightly updates" in page.text and "mine rack move" in page.text
    assert f"/batches/{own_batch}" in page.text
    assert "theirs" not in page.text and f"/batches/{other_batch}" not in page.text


async def test_read_only_user_has_no_calendar(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    assert (await client.get("/scheduling/calendar")).status_code == 403
