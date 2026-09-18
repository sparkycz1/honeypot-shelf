"""`app.tasks.jobs._ping_all_honeypots` — the unavailability/recovered
notification hook: a matching `NotificationRule` gets one "it's down"
notification per continuous outage, once it's lasted at least the rule's
own `unavailable_after_minutes`, and one "it's back" notification once
it's been reachable again for at least `recovered_after_minutes`."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.notification_rule_state import NotificationRuleState
from app.db.models.user import AuthProvider, User
from app.ssh.reachability import ReachabilityResult
from app.tasks.jobs import _ping_all_honeypots
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _setup_honeypot_and_rule(
    db_session_factory,
    *,
    unreachable_since: datetime | None,
    reachable_since: datetime | None = None,
    unavailable_after_minutes: int = 10,
    recovered_after_minutes: int = 5,
):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        # `is_reachable` reflects what the *previous* sweep already found,
        # matching whichever of unreachable_since/reachable_since is set —
        # otherwise `_ping_all_honeypots`'s own "first ever check" branch
        # would reset reachable_since/unreachable_since to "now" on the
        # very next sweep, clobbering the debounce clock this fixture is
        # deliberately backdating.
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="acme-honey1",
            ip_address="203.0.113.7",
            port=22222,
            is_reachable=True if reachable_since else (False if unreachable_since else None),
            unreachable_since=unreachable_since,
            reachable_since=reachable_since,
        )
        db.add(honeypot)

        user = User(
            username="subscriber",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            email="subscriber@example.com",
        )
        db.add(user)
        await db.flush()

        rule = NotificationRule(
            user_id=user.id,
            name="Availability watch",
            scope=NotificationScope.HONEYPOT,
            honeypots=[honeypot],
            notify_on_alert=False,
            notify_on_unavailable=True,
            unavailable_after_minutes=unavailable_after_minutes,
            notify_on_recovered=True,
            recovered_after_minutes=recovered_after_minutes,
        )
        db.add(rule)

        app_settings = await get_or_create_app_settings(db)
        app_settings.smtp_enabled = True
        app_settings.smtp_host = "smtp.example.com"

        await db.commit()
        honeypot_id, rule_id = honeypot.id, rule.id
    return honeypot_id, rule_id


async def _state(db_session_factory, rule_id, honeypot_id) -> NotificationRuleState | None:
    from sqlalchemy import select

    async with db_session_factory() as db:
        result = await db.execute(
            select(NotificationRuleState).where(
                NotificationRuleState.rule_id == rule_id,
                NotificationRuleState.honeypot_id == honeypot_id,
            )
        )
        return result.scalar_one_or_none()


async def test_sends_unavailable_notification_once_debounce_elapsed(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=20),
        unavailable_after_minutes=10,
    )

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    calls: list[str] = []

    async def fake_notify_unavailable(app_settings, *, rule, honeypot, threshold_minutes, db=None):
        calls.append(rule.user.username)

    monkeypatch.setattr("app.tasks.jobs.notify_unavailable", fake_notify_unavailable)

    await _ping_all_honeypots()

    assert calls == ["subscriber"]
    state = await _state(db_session_factory, rule_id, honeypot_id)
    assert state is not None
    assert state.unavailable_notified_at is not None


async def test_does_not_send_before_debounce_elapses(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _honeypot_id, _rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=2),
        unavailable_after_minutes=10,
    )

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    called = False

    async def fake_notify_unavailable(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.tasks.jobs.notify_unavailable", fake_notify_unavailable)

    await _ping_all_honeypots()

    assert called is False


async def test_sends_only_one_unavailable_notification_per_outage(db_session_factory, monkeypatch):
    """A second sweep while still down (already notified) must not notify
    again."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=20),
        unavailable_after_minutes=10,
    )
    async with db_session_factory() as db:
        db.add(
            NotificationRuleState(
                rule_id=rule_id,
                honeypot_id=honeypot_id,
                unavailable_notified_at=datetime.now(UTC) - timedelta(minutes=15),
            )
        )
        await db.commit()

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    called = False

    async def fake_notify_unavailable(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.tasks.jobs.notify_unavailable", fake_notify_unavailable)

    await _ping_all_honeypots()

    assert called is False


async def test_sends_recovered_notification_once_its_own_debounce_elapses(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=None,
        reachable_since=datetime.now(UTC) - timedelta(minutes=10),
        recovered_after_minutes=5,
    )
    async with db_session_factory() as db:
        db.add(
            NotificationRuleState(
                rule_id=rule_id,
                honeypot_id=honeypot_id,
                unavailable_notified_at=datetime.now(UTC) - timedelta(minutes=15),
            )
        )
        await db.commit()

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=True, latency_ms=12.3)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    calls: list[tuple[str, int]] = []

    async def fake_notify_recovered(app_settings, *, rule, honeypot, threshold_minutes, db=None):
        calls.append((rule.user.username, threshold_minutes))

    monkeypatch.setattr("app.tasks.jobs.notify_recovered", fake_notify_recovered)

    await _ping_all_honeypots()

    assert calls == [("subscriber", 5)]
    state = await _state(db_session_factory, rule_id, honeypot_id)
    assert state is not None
    assert state.unavailable_notified_at is None
    assert state.recovered_notified_at is not None


async def test_does_not_send_recovered_before_its_own_debounce_elapses(
    db_session_factory, monkeypatch
):
    """Reachable again, but not yet for `recovered_after_minutes` — a
    flapping blip shouldn't immediately claim recovery."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=None,
        reachable_since=datetime.now(UTC) - timedelta(minutes=1),
        recovered_after_minutes=5,
    )
    async with db_session_factory() as db:
        db.add(
            NotificationRuleState(
                rule_id=rule_id,
                honeypot_id=honeypot_id,
                unavailable_notified_at=datetime.now(UTC) - timedelta(minutes=10),
            )
        )
        await db.commit()

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=True, latency_ms=12.3)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    called = False

    async def fake_notify_recovered(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.tasks.jobs.notify_recovered", fake_notify_recovered)

    await _ping_all_honeypots()

    assert called is False
    state = await _state(db_session_factory, rule_id, honeypot_id)
    assert state is not None
    # Still marked as the same ongoing outage/recovery cycle.
    assert state.unavailable_notified_at is not None
    assert state.recovered_notified_at is None


async def test_no_recovered_notification_if_never_notified_unavailable(
    db_session_factory, monkeypatch
):
    """A brief blip that recovers before `unavailable_after_minutes` ever
    elapsed never had an "unavailable" notification sent — so there's
    nothing to report as "recovered" either."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _honeypot_id, _rule_id = await _setup_honeypot_and_rule(
        db_session_factory,
        unreachable_since=None,
        reachable_since=datetime.now(UTC) - timedelta(minutes=10),
        recovered_after_minutes=5,
    )
    # No NotificationRuleState row at all — never got far enough to notify.

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=True, latency_ms=12.3)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    called = False

    async def fake_notify_recovered(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.tasks.jobs.notify_recovered", fake_notify_recovered)

    await _ping_all_honeypots()

    assert called is False
