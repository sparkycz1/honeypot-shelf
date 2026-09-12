"""Web routes for Notifications: `/account/email`, `/account/notifications`
(GET/POST), `/account/notifications/email` — self-service, available to
any logged-in user regardless of access level."""

from __future__ import annotations

import re

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_notification_subscription import HoneypotNotificationSubscription
from app.db.models.user import AccessLevel, AuthProvider, User
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_read_only_user_can_reach_notifications_page(client, login_as, db_session_factory):
    """Explicit product decision: self-service, any access level — not
    gated behind write access."""
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    response = await client.get("/account/notifications")
    assert response.status_code == 200


async def test_update_own_account_email(client):
    form = await client.get("/account")
    response = await client.post(
        "/account/email",
        data={"csrf_token": _csrf_from(form), "email": "me@example.com"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    account_page = await client.get("/account")
    assert "me@example.com" in account_page.text


async def test_update_own_account_email_rejects_malformed_address(client):
    form = await client.get("/account")
    response = await client.post(
        "/account/email",
        data={"csrf_token": _csrf_from(form), "email": "not-an-email"},
    )
    assert response.status_code == 200
    assert "valid email" in response.text.lower()


async def test_update_notification_email_override(client):
    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications/email",
        data={"csrf_token": _csrf_from(form), "notification_email": "alias@example.com"},
        follow_redirects=False,
    )
    assert response.status_code == 303

    page = await client.get("/account/notifications")
    assert "alias@example.com" in page.text


async def test_subscription_form_only_lists_visible_honeypots(
    client, login_as, db_session_factory
):
    own_company = await create_company(db_session_factory, name="Own Co")
    other_company = await create_company(db_session_factory, name="Other Co")
    async with db_session_factory() as db:
        visible = Honeypot(
            companies=[await db.get(Company, own_company.id)], name="visible-honey"
        )
        hidden = Honeypot(
            companies=[await db.get(Company, other_company.id)], name="hidden-honey"
        )
        db.add_all([visible, hidden])
        await db.commit()

    await login_as(client, company_id=own_company.id, access_level=AccessLevel.READ)

    response = await client.get("/account/notifications")
    assert "visible-honey" in response.text
    assert "hidden-honey" not in response.text


async def test_save_subscriptions_creates_and_deletes_rows(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        honeypot_id = honeypot.id

    user = await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            f"alert_{honeypot_id}": "on",
            f"unavailable_{honeypot_id}": "on",
            f"minutes_{honeypot_id}": "15",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        result = await db.execute(
            HoneypotNotificationSubscription.__table__.select().where(
                HoneypotNotificationSubscription.user_id == user.id,
                HoneypotNotificationSubscription.honeypot_id == honeypot_id,
            )
        )
        row = result.one()
        assert row.notify_on_alert is True
        assert row.notify_on_unavailable is True
        assert row.unavailable_after_minutes == 15

    # Unchecking both boxes deletes the row rather than keeping an
    # all-False no-op around.
    form2 = await client.get("/account/notifications")
    await client.post(
        "/account/notifications",
        data={"csrf_token": _csrf_from(form2)},
        follow_redirects=False,
    )
    async with db_session_factory() as db:
        result = await db.execute(
            HoneypotNotificationSubscription.__table__.select().where(
                HoneypotNotificationSubscription.user_id == user.id,
                HoneypotNotificationSubscription.honeypot_id == honeypot_id,
            )
        )
        assert result.one_or_none() is None


async def test_notification_target_email_property(db_session_factory):
    async with db_session_factory() as db:
        user = User(
            username="prop-test", auth_provider=AuthProvider.LOCAL, email="acct@example.com"
        )
        db.add(user)
        await db.flush()
        assert user.notification_target_email == "acct@example.com"
        user.notification_email = "override@example.com"
        assert user.notification_target_email == "override@example.com"
