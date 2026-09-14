"""Webhook delivery, "Send test", and notification history — extensions
to Notifications ported from an identical debcontrol feature (a1c962b:
webhook delivery, notification history/retention, send-test button),
adapted to this app's per-(user, honeypot) subscription model (see
`app.services.notifications`'s module docstring)."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_notification_subscription import HoneypotNotificationSubscription
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.user import AuthProvider, User
from app.services.webhook import UnsafeWebhookTargetError, validate_webhook_url
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


# --- validate_webhook_url (SSRF guard) --------------------------------------


def test_validate_webhook_url_rejects_non_http_scheme():
    with pytest.raises(UnsafeWebhookTargetError):
        validate_webhook_url("ftp://example.com/hook")


def test_validate_webhook_url_rejects_loopback():
    with pytest.raises(UnsafeWebhookTargetError):
        validate_webhook_url("http://127.0.0.1:8080/hook")


def test_validate_webhook_url_rejects_link_local_metadata_address():
    with pytest.raises(UnsafeWebhookTargetError):
        validate_webhook_url("http://169.254.169.254/latest/meta-data")


def test_validate_webhook_url_rejects_private_hostname():
    with pytest.raises(UnsafeWebhookTargetError):
        validate_webhook_url("http://localhost/hook")


def test_validate_webhook_url_accepts_a_public_address():
    # 93.184.216.34 is example.com's long-standing public IP — resolving a
    # real public hostname requires DNS the test sandbox may not have, so
    # this validates a URL whose hostname is already a public IP literal.
    validate_webhook_url("https://93.184.216.34/hook")


# --- Saving a subscription with delivery_channel=webhook -------------------


async def _make_honeypot(db_session_factory, *, name: str = "acme-honey1"):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name=name)
        db.add(honeypot)
        await db.commit()
        return honeypot.id


async def test_saving_a_webhook_subscription_persists_channel_and_url(
    client, db_session_factory
):
    honeypot_id = await _make_honeypot(db_session_factory)
    form = await client.get("/account/notifications")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": csrf_token,
            f"alert_{honeypot_id}": "on",
            f"channel_{honeypot_id}": "webhook",
            f"webhook_{honeypot_id}": "https://93.184.216.34/hook",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(HoneypotNotificationSubscription))
        sub = result.scalar_one()
        assert sub.delivery_channel == NotificationChannel.WEBHOOK
        assert sub.webhook_url == "https://93.184.216.34/hook"


async def test_saving_a_webhook_subscription_with_an_unsafe_url_is_rejected(
    client, db_session_factory
):
    honeypot_id = await _make_honeypot(db_session_factory)
    form = await client.get("/account/notifications")
    csrf_token = _csrf_from(form)

    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": csrf_token,
            f"alert_{honeypot_id}": "on",
            f"channel_{honeypot_id}": "webhook",
            f"webhook_{honeypot_id}": "http://127.0.0.1/hook",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "non-public address" in response.text

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(HoneypotNotificationSubscription))
        assert result.scalar_one_or_none() is None


# --- "Send test" -------------------------------------------------------------


async def test_send_test_notification_logs_a_test_entry(client, db_session_factory, monkeypatch):
    honeypot_id = await _make_honeypot(db_session_factory)

    sent: list[tuple[str, str]] = []

    def fake_send_email(app_settings, *, to_address, subject, body):
        sent.append((to_address, subject))

    monkeypatch.setattr("app.services.notifications.send_email", fake_send_email)

    await client.get("/account")
    async with db_session_factory() as db:
        from sqlalchemy import select

        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        user.email = "me@example.com"
        await db.commit()

    form = await client.get("/account/notifications")
    csrf_token = _csrf_from(form)
    response = await client.post(
        f"/account/notifications/test/{honeypot_id}",
        data={"csrf_token": csrf_token, f"channel_{honeypot_id}": "email"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "test_sent=1" in response.headers["location"]
    assert sent, "expected send_email to have been called"

    async with db_session_factory() as db:
        from sqlalchemy import select

        entry = (await db.execute(select(NotificationLog))).scalar_one()
        assert entry.is_test is True
        assert entry.success is True
        assert entry.channel == NotificationChannel.EMAIL


async def test_send_test_notification_for_unseen_honeypot_404s(
    client, db_session_factory, login_as
):
    from app.db.models.user import AccessLevel

    other_company = await create_company(db_session_factory, name="other-co")
    my_company = await create_company(db_session_factory, name="my-co")
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, other_company.id)], name="not-mine")
        db.add(honeypot)
        await db.commit()
        honeypot_id = honeypot.id

    # A plain (non-superadmin) member of a *different* company can't see
    # `honeypot_id` at all — superadmin, this test's default `client`
    # login, can see every honeypot regardless of company, so this needs
    # a scoped-down account to actually exercise the 404 path.
    await login_as(client, company_id=my_company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    csrf_token = _csrf_from(form)
    response = await client.post(
        f"/account/notifications/test/{honeypot_id}",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 404


# --- History -----------------------------------------------------------------


async def test_history_page_only_shows_the_current_users_own_entries(client, db_session_factory):
    honeypot_id = await _make_honeypot(db_session_factory)
    async with db_session_factory() as db:
        other_user = User(
            username="other-user", auth_provider=AuthProvider.LOCAL, is_active=True
        )
        db.add(other_user)
        await db.flush()
        db.add(
            NotificationLog(
                user_id=other_user.id,
                honeypot_id=honeypot_id,
                honeypot_name="acme-honey1",
                kind=NotificationKind.TEST,
                channel=NotificationChannel.EMAIL,
                target="other@example.com",
                success=True,
                is_test=True,
            )
        )
        await db.commit()

    response = await client.get("/account/notifications/history")
    assert response.status_code == 200
    assert "other@example.com" not in response.text
    assert "No notifications have been sent yet." in response.text


# --- Retention purge -----------------------------------------------------


async def test_purge_old_notification_logs_respects_retention_days(
    db_session_factory, monkeypatch
):
    from app.tasks.jobs import _purge_old_notification_logs

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        user = User(username="log-owner", auth_provider=AuthProvider.LOCAL, is_active=True)
        db.add(user)
        await db.flush()

        old_entry = NotificationLog(
            user_id=user.id,
            kind=NotificationKind.TEST,
            channel=NotificationChannel.EMAIL,
            target="old@example.com",
            success=True,
            is_test=True,
        )
        db.add(old_entry)
        await db.flush()
        old_entry.created_at = datetime.now(UTC) - timedelta(days=200)

        db.add(
            NotificationLog(
                user_id=user.id,
                kind=NotificationKind.TEST,
                channel=NotificationChannel.EMAIL,
                target="recent@example.com",
                success=True,
                is_test=True,
            )
        )
        app_settings = await get_or_create_app_settings(db)
        app_settings.notification_log_retention_days = 90
        await db.commit()

    await _purge_old_notification_logs()

    async with db_session_factory() as db:
        from sqlalchemy import select

        remaining = (await db.execute(select(NotificationLog.target))).scalars().all()
        assert remaining == ["recent@example.com"]


async def test_purge_old_notification_logs_is_a_noop_when_retention_unset(
    db_session_factory, monkeypatch
):
    from app.tasks.jobs import _purge_old_notification_logs

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        user = User(username="log-owner2", auth_provider=AuthProvider.LOCAL, is_active=True)
        db.add(user)
        await db.flush()
        entry = NotificationLog(
            user_id=user.id,
            kind=NotificationKind.TEST,
            channel=NotificationChannel.EMAIL,
            target="forever@example.com",
            success=True,
            is_test=True,
        )
        db.add(entry)
        await db.flush()
        entry.created_at = datetime.now(UTC) - timedelta(days=2000)
        app_settings = await get_or_create_app_settings(db)
        app_settings.notification_log_retention_days = None
        await db.commit()

    await _purge_old_notification_logs()

    async with db_session_factory() as db:
        from sqlalchemy import select

        remaining = (await db.execute(select(NotificationLog.target))).scalars().all()
        assert remaining == ["forever@example.com"]
