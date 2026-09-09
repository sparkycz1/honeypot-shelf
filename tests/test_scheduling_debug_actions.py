"""Two new schedulable actions for on-demand remote debugging: force an
immediate OpenCanary log poll, or an immediate monitoring sample —
alongside the existing "send command"/"update"/"power" actions. See
`app.scheduling.builtin_actions`/`app.services.honeypot_actions`."""

from __future__ import annotations

import pytest

from app.db.models.honeypot import Honeypot
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services.honeypot_actions import trigger_canary_log_poll, trigger_monitoring_sample
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _pinned_honeypot(db_session_factory, company_id) -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company_id, name="acme-honey1", host_key_fingerprint="SHA256:fake"
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_trigger_canary_log_poll_enqueues_only_pinned_honeypots(
    db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    pinned = await _pinned_honeypot(db_session_factory, company.id)
    async with db_session_factory() as db:
        unpinned = Honeypot(company_id=company.id, name="unpinned")
        db.add(unpinned)
        await db.commit()

    skipped = await trigger_canary_log_poll([pinned, unpinned])

    assert skipped == 1
    assert celery_calls.names == ["app.tasks.jobs.poll_honeypot_canary_log"]
    assert celery_calls[0][1] == (str(pinned.id),)


async def test_trigger_monitoring_sample_enqueues_only_pinned_honeypots(
    db_session_factory, celery_calls
):
    company = await create_company(db_session_factory)
    pinned = await _pinned_honeypot(db_session_factory, company.id)

    skipped = await trigger_monitoring_sample([pinned])

    assert skipped == 0
    assert celery_calls.names == ["app.tasks.jobs.sample_honeypot_monitoring"]


async def test_poll_canary_log_and_sample_monitoring_actions_are_registered():
    register_builtin_actions()
    assert get_action("poll_canary_log") is not None
    assert get_action("sample_monitoring") is not None


async def test_poll_canary_log_action_run_delegates_to_the_helper(
    db_session_factory, celery_calls
):
    register_builtin_actions()
    company = await create_company(db_session_factory)
    pinned = await _pinned_honeypot(db_session_factory, company.id)

    action = get_action("poll_canary_log")
    assert action is not None
    async with db_session_factory() as db:
        result = await action.run(db, [pinned], {})

    assert result.attempted == 1
    assert result.skipped == 0
    assert celery_calls.names == ["app.tasks.jobs.poll_honeypot_canary_log"]


async def test_sample_monitoring_action_run_delegates_to_the_helper(
    db_session_factory, celery_calls
):
    register_builtin_actions()
    company = await create_company(db_session_factory)
    pinned = await _pinned_honeypot(db_session_factory, company.id)

    action = get_action("sample_monitoring")
    assert action is not None
    async with db_session_factory() as db:
        result = await action.run(db, [pinned], {})

    assert result.attempted == 1
    assert result.skipped == 0
    assert celery_calls.names == ["app.tasks.jobs.sample_honeypot_monitoring"]
