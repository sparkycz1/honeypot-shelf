"""`app.tasks.jobs._poll_honeypot_canary_log` — the SSH-poll path that
turns `app.ssh.canary_activity.poll_log`'s parsed lines into
`HoneypotEvent` rows. Regression guard for a real bug found live:
OpenCanary's own internal/operational log lines (module-registration and
startup-banner lines, logtype 1000-1006) used to be stored as events too,
flooding the Activity tab with noise — especially bad during a crash-loop,
which logs its own startup banner every few seconds. See
`app.services.opencanary_logtypes.is_internal_logtype`.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.ssh.canary_activity import LogPollResult
from app.tasks.jobs import _poll_honeypot_canary_log
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def test_poll_skips_internal_logtypes_but_keeps_real_alerts(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
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
        honeypot_id = honeypot.id

    fake_result = LogPollResult(
        events=[
            {"logtype": 1001, "local_time": "2026-01-01 12:00:00.000000"},  # internal noise
            {"logtype": 1000, "local_time": "2026-01-01 12:00:01.000000"},  # internal noise
            {
                "logtype": 4002,
                "local_time": "2026-01-01 12:00:02.000000",
                "src_host": "203.0.113.7",
            },  # a real alert
        ],
        new_offset=123,
    )

    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> LogPollResult:
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    result = await _poll_honeypot_canary_log(str(honeypot_id))

    assert result == {"ok": True, "new_events": 1}
    async with db_session_factory() as db:
        events = (await db.execute(select(HoneypotEvent))).scalars().all()
        assert len(events) == 1
        assert events[0].event_type == "4002"

        refreshed = await db.get(Honeypot, honeypot_id)
        assert refreshed is not None
        assert refreshed.opencanary_log_offset == 123
        assert refreshed.last_seen_at is not None


async def test_poll_advances_offset_without_setting_last_seen_when_only_internal(
    db_session_factory, monkeypatch
):
    """A poll that only found OpenCanary's own internal log lines still
    must not count as "the honeypot was seen" — that's reserved for
    actual alert activity, same distinction the Dashboard/Activity tab
    already draw between reachability and event-based liveness."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey2",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        honeypot_id = honeypot.id

    fake_result = LogPollResult(
        events=[{"logtype": 1001, "local_time": "2026-01-01 12:00:00.000000"}],
        new_offset=55,
    )

    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> LogPollResult:
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    result = await _poll_honeypot_canary_log(str(honeypot_id))

    assert result == {"ok": True, "new_events": 0}
    async with db_session_factory() as db:
        assert (await db.execute(select(HoneypotEvent))).scalars().all() == []
        refreshed = await db.get(Honeypot, honeypot_id)
        assert refreshed is not None
        assert refreshed.opencanary_log_offset == 55
        assert refreshed.last_seen_at is None
