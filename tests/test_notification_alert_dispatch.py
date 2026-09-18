"""`app.tasks.jobs._poll_honeypot_canary_log` — the alert-notification hook:
every newly ingested, non-internal `HoneypotEvent` notifies every
`NotificationRule` with `notify_on_alert=True` that matches that honeypot
(directly, or via its company)."""

from __future__ import annotations

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import AuthProvider, User
from app.ssh.canary_activity import LogPollResult
from app.tasks.jobs import _poll_honeypot_canary_log
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _setup(db_session_factory, *, smtp_enabled: bool = True):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="acme-honey1",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)

        subscribed_user = User(
            username="subscribed-user",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            email="subscribed@example.com",
        )
        unsubscribed_user = User(
            username="unsubscribed-user",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            email="unsubscribed@example.com",
        )
        db.add_all([subscribed_user, unsubscribed_user])
        await db.flush()

        db.add(
            NotificationRule(
                user_id=subscribed_user.id,
                name="Alerts",
                scope=NotificationScope.HONEYPOT,
                honeypots=[honeypot],
                notify_on_alert=True,
            )
        )
        db.add(
            NotificationRule(
                user_id=unsubscribed_user.id,
                name="No alerts",
                scope=NotificationScope.HONEYPOT,
                honeypots=[honeypot],
                notify_on_alert=False,
            )
        )

        app_settings = await get_or_create_app_settings(db)
        app_settings.smtp_enabled = smtp_enabled
        app_settings.smtp_host = "smtp.example.com"

        await db.commit()
        # Not a redundant assignment (RET504) — `commit()`'s default
        # expire_on_commit means `honeypot.id` needs the still-open
        # session to refresh from, so it has to be captured *inside* this
        # `with` block; the `return` itself is outside it, once the
        # session (and any lazy-load chance) is already gone.
        honeypot_id = honeypot.id
    return honeypot_id  # noqa: RET504


async def test_new_alert_emails_only_subscribed_active_recipients(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _setup(db_session_factory)

    fake_result = LogPollResult(
        events=[
            {"logtype": 4002, "local_time": "2026-01-01 12:00:00.000000", "src_host": "203.0.113.7"}
        ],
        new_offset=1,
    )

    async def fake_poll_log(honeypot, secret, timeout_seconds, *, path=""):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    sent_to: list[str] = []

    async def fake_notify_alert(app_settings, *, rules, honeypot, **kwargs):
        sent_to.extend(rule.user.username for rule in rules)

    monkeypatch.setattr("app.tasks.jobs.notify_alert", fake_notify_alert)

    result = await _poll_honeypot_canary_log(str(honeypot_id))

    assert result["ok"] is True
    assert sent_to == ["subscribed-user"]


async def test_no_email_sent_when_smtp_disabled(db_session_factory, monkeypatch):
    """Unlike a webhook rule (which fires regardless — see
    `app.services.notifications.notify_alert`), an email-channel rule
    must not actually send when SMTP is off. `notify_alert` itself is
    still called (and still queries matching rules) — it's the
    per-rule dispatch inside it that skips the send — so this patches the
    real send function rather than `notify_alert` itself."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _setup(db_session_factory, smtp_enabled=False)

    fake_result = LogPollResult(
        events=[{"logtype": 4002, "local_time": "2026-01-01 12:00:00.000000"}],
        new_offset=1,
    )

    async def fake_poll_log(honeypot, secret, timeout_seconds, *, path=""):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    called = False

    def fake_send_email(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.services.notifications.send_email", fake_send_email)

    await _poll_honeypot_canary_log(str(honeypot_id))

    assert called is False


async def test_no_new_events_means_no_rule_query_needed(db_session_factory, monkeypatch):
    """A poll finding zero new alert-worthy events shouldn't even attempt to
    notify anyone — a cheap early-out, not just "zero matching rules"."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _setup(db_session_factory)

    fake_result = LogPollResult(events=[], new_offset=1)

    async def fake_poll_log(honeypot, secret, timeout_seconds, *, path=""):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    called = False

    async def fake_notify_alert(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.tasks.jobs.notify_alert", fake_notify_alert)

    await _poll_honeypot_canary_log(str(honeypot_id))

    assert called is False


async def test_company_scoped_rule_matches_a_honeypot_in_that_company(
    db_session_factory, monkeypatch
):
    """A rule scoped to the whole company fires for any honeypot in it —
    the point of company scope over a per-honeypot subscription."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="acme-honey2",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        user = User(
            username="company-watcher", auth_provider=AuthProvider.LOCAL, is_active=True,
            email="watcher@example.com",
        )
        db.add(user)
        await db.flush()
        db.add(
            NotificationRule(
                user_id=user.id,
                name="Company watch",
                scope=NotificationScope.COMPANY,
                companies=[await db.get(Company, company.id)],
                notify_on_alert=True,
            )
        )
        app_settings = await get_or_create_app_settings(db)
        app_settings.smtp_enabled = True
        app_settings.smtp_host = "smtp.example.com"
        await db.commit()
        honeypot_id = honeypot.id

    fake_result = LogPollResult(
        events=[{"logtype": 4002, "local_time": "2026-01-01 12:00:00.000000"}], new_offset=1
    )

    async def fake_poll_log(honeypot, secret, timeout_seconds, *, path=""):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    sent_to: list[str] = []

    async def fake_notify_alert(app_settings, *, rules, honeypot, **kwargs):
        sent_to.extend(rule.user.username for rule in rules)

    monkeypatch.setattr("app.tasks.jobs.notify_alert", fake_notify_alert)

    await _poll_honeypot_canary_log(str(honeypot_id))

    assert sent_to == ["company-watcher"]


async def test_honeypot_scoped_rule_covering_multiple_honeypots_matches_either(
    db_session_factory, monkeypatch
):
    """A honeypot-scoped rule can now list more than one honeypot — it
    should fire for an event on any of them, not just the first."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        c = await db.get(Company, company.id)
        honeypot_a = Honeypot(
            companies=[c], name="acme-honey-a", host_key_fingerprint="SHA256:fakefingerprint"
        )
        honeypot_b = Honeypot(
            companies=[c], name="acme-honey-b", host_key_fingerprint="SHA256:fakefingerprint"
        )
        db.add_all([honeypot_a, honeypot_b])
        user = User(
            username="multi-honeypot-watcher",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            email="watcher2@example.com",
        )
        db.add(user)
        await db.flush()
        db.add(
            NotificationRule(
                user_id=user.id,
                name="Two honeypots",
                scope=NotificationScope.HONEYPOT,
                honeypots=[honeypot_a, honeypot_b],
                notify_on_alert=True,
            )
        )
        app_settings = await get_or_create_app_settings(db)
        app_settings.smtp_enabled = True
        app_settings.smtp_host = "smtp.example.com"
        await db.commit()
        honeypot_b_id = honeypot_b.id

    fake_result = LogPollResult(
        events=[{"logtype": 4002, "local_time": "2026-01-01 12:00:00.000000"}], new_offset=1
    )

    async def fake_poll_log(honeypot, secret, timeout_seconds, *, path=""):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    sent_to: list[str] = []

    async def fake_notify_alert(app_settings, *, rules, honeypot, **kwargs):
        sent_to.extend(rule.user.username for rule in rules)

    monkeypatch.setattr("app.tasks.jobs.notify_alert", fake_notify_alert)

    # Only the *second* honeypot in the rule gets the event — the rule
    # should still match, since it isn't scoped to just the first one.
    await _poll_honeypot_canary_log(str(honeypot_b_id))

    assert sent_to == ["multi-honeypot-watcher"]
