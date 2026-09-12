"""Settings → Checks & retention (`app.web.routes.settings.update_checks_settings`)
— the SSH connect/update-run timeouts, the four background-check
intervals, and the reachability sweep's concurrency cap, all moved here
from environment variables per an explicit product decision (ported from
an identical debcontrol change; see `app/db/models/app_settings.py`)."""

from __future__ import annotations

import re

import pytest

from app.core.app_settings import get_or_create_app_settings

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_checks_tab_renders_current_values(client):
    response = await client.get("/settings", params={"tab": "checks"})
    assert response.status_code == 200
    assert 'value="10"' in response.text  # ssh_connect_timeout default
    assert 'value="1800"' in response.text  # update_timeout_seconds default


async def test_update_checks_settings_saves_new_values(client, db_session_factory):
    form = await client.get("/settings", params={"tab": "checks"})
    response = await client.post(
        "/settings/checks",
        data={
            "csrf_token": _csrf_from(form),
            "ssh_connect_timeout": "15",
            "update_timeout_seconds": "3600",
            "facts_refresh_interval_seconds": "900",
            "reachability_check_interval_seconds": "30",
            "reachability_check_concurrency": "10",
            "monitoring_interval_seconds": "180",
            "opencanary_log_poll_interval_seconds": "60",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=checks"

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.ssh_connect_timeout == 15
        assert app_settings.update_timeout_seconds == 3600
        assert app_settings.facts_refresh_interval_seconds == 900
        assert app_settings.reachability_check_interval_seconds == 30
        assert app_settings.reachability_check_concurrency == 10
        assert app_settings.monitoring_interval_seconds == 180
        assert app_settings.opencanary_log_poll_interval_seconds == 60


async def test_update_checks_settings_rejects_out_of_range_value(client, db_session_factory):
    """`ssh_connect_timeout`'s upper bound (300s) exists so it stays safely
    under Celery's own fixed per-task time limit
    (`app.tasks.jobs._SSH_TASK_TIME_LIMIT_SECONDS`) — a value above it is
    rejected, not silently clamped."""
    form = await client.get("/settings", params={"tab": "checks"})
    response = await client.post(
        "/settings/checks",
        data={
            "csrf_token": _csrf_from(form),
            "ssh_connect_timeout": "999999",
            "update_timeout_seconds": "1800",
            "facts_refresh_interval_seconds": "600",
            "reachability_check_interval_seconds": "60",
            "reachability_check_concurrency": "20",
            "monitoring_interval_seconds": "120",
            "opencanary_log_poll_interval_seconds": "120",
        },
    )
    assert response.status_code == 200
    assert "must be between" in response.text

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        # Unchanged — a rejected form never partially applies.
        assert app_settings.ssh_connect_timeout == 10


async def test_retention_forms_now_live_on_the_checks_tab(client):
    """The four retention-day settings moved out of Security into Checks &
    retention alongside the new background-check fields."""
    response = await client.get("/settings", params={"tab": "checks"})
    assert response.status_code == 200
    assert 'id="retention_days"' in response.text
    assert 'id="dashboard_trends_retention_days"' in response.text
    assert 'id="honeypot_update_run_retention_days"' in response.text
    assert 'id="monitoring_history_retention_days"' in response.text

    security_response = await client.get("/settings", params={"tab": "security"})
    assert security_response.status_code == 200
    assert 'id="dashboard_trends_retention_days"' not in security_response.text
