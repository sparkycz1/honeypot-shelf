"""Web routes for Notifications: `/account/email`, `/account/notifications`
(list/create), `/account/notifications/email`, `/{id}/edit`, `/{id}/delete`
— self-service, available to any logged-in user regardless of access
level, each rule scoped to a company or honeypot the owner can see."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_rule import NotificationRule, NotificationScope
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


async def test_rule_form_only_lists_visible_companies_and_honeypots(
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
    assert "Own Co" in response.text
    assert "Other Co" not in response.text
    assert "visible-honey" in response.text
    assert "hidden-honey" not in response.text


async def test_superadmin_sees_every_company(client, db_session_factory):
    await create_company(db_session_factory, name="Alpha Co")
    await create_company(db_session_factory, name="Beta Co")

    response = await client.get("/account/notifications")  # default client is superadmin
    assert "Alpha Co" in response.text
    assert "Beta Co" in response.text


async def test_create_company_scoped_rule(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    user = await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Company-wide alerts",
            "scope": "company",
            "company_id": str(company.id),
            "delivery_channel": "email",
            "notify_on_alert": "on",
            "notify_on_unavailable": "on",
            "unavailable_after_minutes": "15",
            "notify_on_recovered": "on",
            "recovered_after_minutes": "5",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (
            await db.execute(select(NotificationRule).where(NotificationRule.user_id == user.id))
        ).scalar_one()
        assert rule.name == "Company-wide alerts"
        assert rule.scope == NotificationScope.COMPANY
        assert rule.company_id == company.id
        assert rule.unavailable_after_minutes == 15


async def test_create_honeypot_scoped_rule(client, login_as, db_session_factory):
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
            "name": "Just this honeypot",
            "scope": "honeypot",
            "honeypot_id": str(honeypot_id),
            "delivery_channel": "email",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (
            await db.execute(select(NotificationRule).where(NotificationRule.user_id == user.id))
        ).scalar_one()
        assert rule.scope == NotificationScope.HONEYPOT
        assert rule.honeypot_id == honeypot_id


async def test_cannot_create_rule_scoped_to_a_company_not_visible(
    client, login_as, db_session_factory
):
    own_company = await create_company(db_session_factory, name="Own")
    other_company = await create_company(db_session_factory, name="Other")
    await login_as(client, company_id=own_company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Sneaky rule",
            "scope": "company",
            "company_id": str(other_company.id),
            "delivery_channel": "email",
            "notify_on_alert": "on",
        },
    )
    assert response.status_code == 200
    assert "have access to that company" in response.text

    async with db_session_factory() as db:
        assert (await db.execute(select(NotificationRule))).scalar_one_or_none() is None


async def test_webhook_rule_rejects_unsafe_url(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Bad webhook",
            "scope": "company",
            "company_id": str(company.id),
            "delivery_channel": "webhook",
            "webhook_url": "http://127.0.0.1/hook",
            "notify_on_alert": "on",
        },
    )
    assert response.status_code == 200
    assert "non-public address" in response.text


async def test_edit_and_delete_own_rule(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    user = await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    async with db_session_factory() as db:
        rule = NotificationRule(
            user_id=user.id,
            name="Original name",
            scope=NotificationScope.COMPANY,
            company_id=company.id,
            notify_on_alert=True,
        )
        db.add(rule)
        await db.commit()
        rule_id = rule.id

    form = await client.get("/account/notifications")
    response = await client.post(
        f"/account/notifications/{rule_id}/edit",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Renamed",
            "scope": "company",
            "company_id": str(company.id),
            "delivery_channel": "email",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(NotificationRule, rule_id)
        assert refreshed is not None
        assert refreshed.name == "Renamed"

    form2 = await client.get("/account/notifications")
    response = await client.post(
        f"/account/notifications/{rule_id}/delete",
        data={"csrf_token": _csrf_from(form2)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        assert await db.get(NotificationRule, rule_id) is None


async def test_cannot_edit_or_delete_another_users_rule(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    from tests.conftest import _create_user

    owner, _ = await _create_user(db_session_factory, username="rule-owner")
    async with db_session_factory() as db:
        rule = NotificationRule(
            user_id=owner.id,
            name="Not yours",
            scope=NotificationScope.COMPANY,
            company_id=company.id,
            notify_on_alert=True,
        )
        db.add(rule)
        await db.commit()
        rule_id = rule.id

    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    form = await client.get("/account/notifications")
    response = await client.post(
        f"/account/notifications/{rule_id}/delete",
        data={"csrf_token": _csrf_from(form)},
    )
    assert response.status_code == 404


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
