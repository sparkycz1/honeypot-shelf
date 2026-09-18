"""Web routes for Notifications: `/account/email`, `/account/notifications`
(list/create), `/{id}/edit`, `/{id}/delete` — self-service, available to
any logged-in user regardless of access level, each rule scoped to a
company or honeypot the owner can see."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import AccessLevel, AuthProvider, User
from app.services.notifications import resolve_target
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
            "company_ids": str(company.id),
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
        assert [c.id for c in rule.companies] == [company.id]
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
            "honeypot_ids": str(honeypot_id),
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
        assert [h.id for h in rule.honeypots] == [honeypot_id]


async def test_create_rule_scoped_to_multiple_companies(client, db_session_factory):
    """A rule can cover any number of companies at once, not just one —
    each submitted as its own `company_ids` form value (a multi-select
    posts one entry per selection)."""
    alpha = await create_company(db_session_factory, name="Alpha Co")
    beta = await create_company(db_session_factory, name="Beta Co")

    form = await client.get("/account/notifications")  # default client is superadmin
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Two companies",
            "scope": "company",
            "company_ids": [str(alpha.id), str(beta.id)],
            "delivery_channel": "email",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.scope == NotificationScope.COMPANY
        assert {c.id for c in rule.companies} == {alpha.id, beta.id}


async def test_create_rule_scoped_to_multiple_honeypots(client, db_session_factory):
    """Same as above, for honeypot scope."""
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        c = await db.get(Company, company.id)
        hp1 = Honeypot(companies=[c], name="honey-one")
        hp2 = Honeypot(companies=[c], name="honey-two")
        db.add_all([hp1, hp2])
        await db.commit()
        hp1_id, hp2_id = hp1.id, hp2.id

    form = await client.get("/account/notifications")  # default client is superadmin
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Two honeypots",
            "scope": "honeypot",
            "honeypot_ids": [str(hp1_id), str(hp2_id)],
            "delivery_channel": "email",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.scope == NotificationScope.HONEYPOT
        assert {h.id for h in rule.honeypots} == {hp1_id, hp2_id}


async def test_create_rule_with_custom_wording_persists_the_override(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    user = await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Custom wording",
            "scope": "company",
            "company_ids": str(company.id),
            "delivery_channel": "email",
            "notify_on_alert": "on",
            "alert_subject": "Heads up: {honeypot_name}",
            "alert_body": "Something happened on {honeypot_name}.",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (
            await db.execute(select(NotificationRule).where(NotificationRule.user_id == user.id))
        ).scalar_one()
        assert rule.alert_subject == "Heads up: {honeypot_name}"
        assert rule.alert_body == "Something happened on {honeypot_name}."
        # Never customized — stays None, so it renders from the built-in
        # default in the rule owner's own language at send time.
        assert rule.unavailable_subject is None
        assert rule.unavailable_body is None


async def test_create_rule_without_custom_wording_leaves_it_unset(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    user = await login_as(client, company_id=company.id, access_level=AccessLevel.READ)

    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Defaults only",
            "scope": "company",
            "company_ids": str(company.id),
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
        assert rule.alert_subject is None
        assert rule.alert_body is None


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
            "company_ids": str(other_company.id),
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
            "company_ids": str(company.id),
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
            companies=[await db.get(Company, company.id)],
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
            "company_ids": str(company.id),
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
            companies=[await db.get(Company, company.id)],
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


async def test_settings_no_longer_offers_a_notifications_tab(client):
    """The instance-wide template editor moved into each rule's own
    wording section — Settings' "Notifications" tab (and its
    /settings/notifications/templates route) is gone."""
    response = await client.get("/settings?tab=notifications")
    assert response.status_code == 200
    # An unrecognized tab value falls back to "general" rather than
    # 404ing or rendering nothing — see settings.py's `_normalize_tab`.
    assert '?tab=notifications' not in response.text

    form = await client.get("/settings")
    csrf_token = _csrf_from(form)
    stale_post = await client.post(
        "/settings/notifications/templates",
        data={"csrf_token": csrf_token, "notification_alert_subject": "x"},
    )
    assert stale_post.status_code == 404


async def test_resolve_target_falls_back_to_account_email(db_session_factory):
    """A rule with no `target_email` of its own resolves to the owner's
    plain account email — there's no separate notification-email override
    any more, the per-rule field is the only place to pick a different
    address (see the Notifications page's own hint)."""
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        user = User(
            username="resolve-test", auth_provider=AuthProvider.LOCAL, email="acct@example.com"
        )
        db.add(user)
        await db.flush()
        rule = NotificationRule(
            user_id=user.id,
            name="r",
            scope=NotificationScope.COMPANY,
            companies=[await db.get(Company, company.id)],
            notify_on_alert=True,
        )
        db.add(rule)
        await db.flush()
        rule.user = user
        assert resolve_target(rule) == "acct@example.com"
        rule.target_email = "override@example.com"
        assert resolve_target(rule) == "override@example.com"
