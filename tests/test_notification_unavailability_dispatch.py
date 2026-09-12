"""`app.tasks.jobs._ping_all_honeypots` — the unavailability-notification
hook added alongside `HoneypotNotificationSubscription`: a subscriber gets
one "it's down" email per continuous outage, once it's lasted at least
their own `unavailable_after_minutes`, and one "it's back" email when it
recovers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_notification_subscription import HoneypotNotificationSubscription
from app.db.models.user import AuthProvider, User
from app.ssh.reachability import ReachabilityResult
from app.tasks.jobs import _ping_all_honeypots
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _setup_honeypot_and_subscriber(
    db_session_factory, *, unreachable_since: datetime | None, unavailable_after_minutes: int = 10
):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="acme-honey1",
            ip_address="203.0.113.7",
            port=22222,
            is_reachable=False if unreachable_since else None,
            unreachable_since=unreachable_since,
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

        sub = HoneypotNotificationSubscription(
            user_id=user.id,
            honeypot_id=honeypot.id,
            notify_on_unavailable=True,
            unavailable_after_minutes=unavailable_after_minutes,
        )
        db.add(sub)

        app_settings = await get_or_create_app_settings(db)
        app_settings.smtp_enabled = True
        app_settings.smtp_host = "smtp.example.com"

        await db.commit()
        honeypot_id, sub_id = honeypot.id, sub.id
    return honeypot_id, sub_id


async def test_sends_unavailable_email_once_debounce_elapsed(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, sub_id = await _setup_honeypot_and_subscriber(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=20),
        unavailable_after_minutes=10,
    )

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    calls: list[str] = []

    async def fake_notify_unavailable(app_settings, *, user, honeypot, threshold_minutes):
        calls.append(user.username)

    monkeypatch.setattr("app.tasks.jobs.notify_unavailable", fake_notify_unavailable)

    await _ping_all_honeypots()

    assert calls == ["subscriber"]

    async with db_session_factory() as db:
        refreshed_sub = await db.get(HoneypotNotificationSubscription, sub_id)
        assert refreshed_sub is not None
        assert refreshed_sub.unavailable_notified_at is not None


async def test_does_not_send_before_debounce_elapses(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, _sub_id = await _setup_honeypot_and_subscriber(
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


async def test_sends_only_one_unavailable_email_per_outage(db_session_factory, monkeypatch):
    """A second sweep while still down (already notified) must not email
    again."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, sub_id = await _setup_honeypot_and_subscriber(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=20),
        unavailable_after_minutes=10,
    )
    async with db_session_factory() as db:
        sub = await db.get(HoneypotNotificationSubscription, sub_id)
        assert sub is not None
        sub.unavailable_notified_at = datetime.now(UTC) - timedelta(minutes=15)
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


async def test_sends_recovered_email_and_clears_state_on_recovery(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id, sub_id = await _setup_honeypot_and_subscriber(
        db_session_factory,
        unreachable_since=datetime.now(UTC) - timedelta(minutes=20),
        unavailable_after_minutes=10,
    )
    async with db_session_factory() as db:
        sub = await db.get(HoneypotNotificationSubscription, sub_id)
        assert sub is not None
        sub.unavailable_notified_at = datetime.now(UTC) - timedelta(minutes=15)
        await db.commit()

    async def fake_check_reachable(ip_address, port):
        return ReachabilityResult(reachable=True, latency_ms=12.3)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    calls: list[str] = []

    async def fake_notify_recovered(app_settings, *, user, honeypot):
        calls.append(user.username)

    monkeypatch.setattr("app.tasks.jobs.notify_recovered", fake_notify_recovered)

    await _ping_all_honeypots()

    assert calls == ["subscriber"]

    async with db_session_factory() as db:
        refreshed_sub = await db.get(HoneypotNotificationSubscription, sub_id)
        assert refreshed_sub is not None
        assert refreshed_sub.unavailable_notified_at is None

        refreshed_honeypot = await db.get(Honeypot, honeypot_id)
        assert refreshed_honeypot is not None
        assert refreshed_honeypot.unreachable_since is None
