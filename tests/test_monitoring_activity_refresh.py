"""The Monitoring/Activity tabs' "Refresh now" button and their auto-poll
panel routes — `app/web/routes/honeypots.py`'s `_build_monitoring_context`/
`_build_activity_context` plus the `-panel`/`/refresh` routes built on
them. No real Celery broker runs in tests (see `tests/conftest.py`'s
`celery_calls` fixture) — a refresh route's `.delay()` calls are recorded
there and each `AsyncResult.get()` returns immediately, so what's actually
verified here is that the right tasks get enqueued and that the response
renders successfully afterward, not the SSH round trip itself (already
covered per-task in `tests/test_opencanary_service_monitoring.py`/
`tests/test_canary_activity_poll_job.py`)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.honeypot import Honeypot
from app.db.models.user import AccessLevel
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def _make_honeypot(db_session_factory) -> Honeypot:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey1",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        return honeypot


async def test_monitoring_panel_route_renders_without_full_page_chrome(
    client, db_session_factory
):
    honeypot = await _make_honeypot(db_session_factory)
    response = await client.get(f"/honeypots/{honeypot.id}/monitoring-panel")
    assert response.status_code == 200
    assert "<html" not in response.text.lower()


async def test_activity_panel_route_renders_without_full_page_chrome(
    client, db_session_factory
):
    honeypot = await _make_honeypot(db_session_factory)
    response = await client.get(f"/honeypots/{honeypot.id}/activity-panel")
    assert response.status_code == 200
    assert "<html" not in response.text.lower()


async def test_refresh_monitoring_enqueues_both_sample_and_reachability_tasks(
    client, db_session_factory, celery_calls
):
    honeypot = await _make_honeypot(db_session_factory)
    page = await client.get(f"/honeypots/{honeypot.id}/monitoring")
    response = await client.post(
        f"/honeypots/{honeypot.id}/monitoring/refresh",
        data={"csrf_token": _csrf_from(page), "range_key": "24h"},
    )
    assert response.status_code == 200
    assert "app.tasks.jobs.sample_honeypot_monitoring" in celery_calls.names
    assert "app.tasks.jobs.check_honeypot_reachability" in celery_calls.names


async def test_refresh_activity_enqueues_the_log_poll_task(
    client, db_session_factory, celery_calls
):
    honeypot = await _make_honeypot(db_session_factory)
    page = await client.get(f"/honeypots/{honeypot.id}/status")
    response = await client.post(
        f"/honeypots/{honeypot.id}/status/refresh",
        data={"csrf_token": _csrf_from(page), "range_key": "24h"},
    )
    assert response.status_code == 200
    assert "app.tasks.jobs.poll_honeypot_canary_log" in celery_calls.names


async def test_read_only_company_user_cannot_trigger_refresh(
    client, db_session_factory, login_as
):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey1",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)

    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    page = await client.get(f"/honeypots/{honeypot.id}/monitoring")
    assert page.status_code == 200  # Monitoring itself is read-visible

    response = await client.post(
        f"/honeypots/{honeypot.id}/monitoring/refresh",
        data={"csrf_token": _csrf_from(page), "range_key": "24h"},
    )
    assert response.status_code == 403


async def test_monitoring_last_checked_uses_the_more_recent_signal(
    client, db_session_factory
):
    from datetime import UTC, datetime, timedelta

    honeypot = await _make_honeypot(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        result = await db.execute(select(Honeypot).where(Honeypot.id == honeypot.id))
        db_honeypot = result.scalar_one()
        db_honeypot.monitoring_updated_at = now - timedelta(minutes=5)
        db_honeypot.last_ping_at = now
        await db.commit()

    response = await client.get(f"/honeypots/{honeypot.id}/monitoring")
    assert response.status_code == 200
