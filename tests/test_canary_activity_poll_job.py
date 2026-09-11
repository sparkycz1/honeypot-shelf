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

from app.db.models.company import Company
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


async def test_poll_still_marks_the_honeypot_seen_when_only_internal_lines_found(
    db_session_factory, monkeypatch
):
    """A poll that only found OpenCanary's own internal log lines stores no
    `HoneypotEvent` (that's reserved for real alert activity), but it DOES
    still count as "the honeypot was seen" — reaching and reading the log
    at all is itself proof OpenCanary is up, exactly like a push to the
    ingest endpoint counts as "seen" regardless of that event's own
    logtype. A quiet, healthy honeypot with no attacker traffic yet must
    not sit stuck "offline" on the Dashboard just because it has nothing
    to alert about — see `app.tasks.jobs._poll_honeypot_canary_log`'s own
    comment for the full reasoning; this replaces a real bug where exactly
    that used to happen."""
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
        assert refreshed.last_seen_at is not None


async def test_poll_does_not_mark_seen_when_the_read_itself_failed(
    db_session_factory, monkeypatch
):
    """`new_offset == -1` means the read didn't even produce the expected
    marker (e.g. the log file is missing, or the connection dropped
    mid-read) — that must not be reported as "seen" the way a genuinely
    successful-but-empty poll is."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey3",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        honeypot_id = honeypot.id

    fake_result = LogPollResult(events=[], new_offset=-1)

    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> LogPollResult:
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    result = await _poll_honeypot_canary_log(str(honeypot_id))

    assert result == {"ok": True, "new_events": 0}
    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot_id)
        assert refreshed is not None
        assert refreshed.opencanary_log_offset == 0
        assert refreshed.last_seen_at is None


async def test_poll_forwards_each_real_alert_to_the_companys_syslog_target(
    db_session_factory, monkeypatch
):
    """Same company-scoped syslog forwarding the push-ingest path gets
    (see tests/test_ingest.py) — the SSH-poll path must forward too,
    since it's just as valid a way for a real alert to arrive."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        company = Company(
            name="Acme", syslog_enabled=True, syslog_host="siem.acme.example.com"
        )
        db.add(company)
        await db.flush()
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey4",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        honeypot_id = honeypot.id

    fake_result = LogPollResult(
        events=[
            {"logtype": 1001, "local_time": "2026-01-01 12:00:00.000000"},  # internal noise
            {
                "logtype": 4002,
                "local_time": "2026-01-01 12:00:02.000000",
                "src_host": "203.0.113.7",
            },  # a real alert
        ],
        new_offset=99,
    )

    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> LogPollResult:
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    forwarded = []

    async def fake_forward(company, honeypot, event):
        forwarded.append((company.name, honeypot.name, event.event_type))

    monkeypatch.setattr("app.tasks.jobs.forward_honeypot_event_to_syslog", fake_forward)

    await _poll_honeypot_canary_log(str(honeypot_id))

    assert forwarded == [("Acme", "acme-honey4", "4002")]
