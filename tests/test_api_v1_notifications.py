"""`/api/v1/notifications` — the token owner's own rules and history,
validated exactly like the web form, scoped like it."""

from __future__ import annotations

from app.auth.api_tokens import create_api_token
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import (
    NotificationChannel,
    NotificationKind,
    NotificationLog,
)
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company


async def _setup(client, login_as, db_session_factory, *, username="api-user"):
    acme = await create_company(db_session_factory, name="Acme")
    beta = await create_company(db_session_factory, name="Beta")
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[acme], name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    user = await login_as(
        client,
        username=username,
        company_id=acme.id,
        access_level=AccessLevel.READ,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    return {"Authorization": f"Bearer {raw}"}, acme, beta, honeypot, user


def _rule(company_id, **extra):
    return {
        "name": "Acme alerts",
        "scope": "company",
        "company_ids": [str(company_id)],
        "notify_on_alert": True,
        "target_email": "soc@example.com",
        **extra,
    }


async def test_read_only_member_creates_lists_updates_and_deletes_own_rule(
    client, login_as, db_session_factory
):
    headers, acme, _beta, _hp, _user = await _setup(client, login_as, db_session_factory)

    created = await client.post(
        "/api/v1/notifications/rules",
        json=_rule(acme.id, alert_event_types=["4002"]),
        headers=headers,
    )
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["company_ids"] == [str(acme.id)]
    assert rule["alert_event_types"] == ["4002"]
    assert rule["has_channel_token"] is False

    listed = await client.get("/api/v1/notifications/rules", headers=headers)
    assert [r["id"] for r in listed.json()] == [rule["id"]]

    updated = await client.put(
        f"/api/v1/notifications/rules/{rule['id']}",
        json=_rule(acme.id, name="Renamed", notify_on_unavailable=True),
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["notify_on_unavailable"] is True

    deleted = await client.delete(f"/api/v1/notifications/rules/{rule['id']}", headers=headers)
    assert deleted.status_code == 204
    rules = await client.get("/api/v1/notifications/rules", headers=headers)
    assert rules.json() == []


async def test_rule_for_a_company_out_of_scope_is_404(client, login_as, db_session_factory):
    headers, _acme, beta, _hp, _user = await _setup(client, login_as, db_session_factory)
    response = await client.post(
        "/api/v1/notifications/rules", json=_rule(beta.id), headers=headers
    )
    assert response.status_code == 404


async def test_invalid_rule_is_422_with_the_form_errors(client, login_as, db_session_factory):
    headers, acme, _beta, _hp, _user = await _setup(client, login_as, db_session_factory)
    response = await client.post(
        "/api/v1/notifications/rules",
        json=_rule(acme.id, notify_on_alert=False),
        headers=headers,
    )
    assert response.status_code == 422
    assert "Pick at least one event to notify on." in response.json()["detail"]


async def test_channel_token_is_write_only_and_kept_on_update(
    client, login_as, db_session_factory
):
    headers, acme, _beta, _hp, _user = await _setup(client, login_as, db_session_factory)
    payload = _rule(
        acme.id,
        delivery_channel="telegram",
        target_email=None,
        channel_token="123:secret",
        channel_recipient="42",
    )
    created = await client.post("/api/v1/notifications/rules", json=payload, headers=headers)
    assert created.status_code == 201, created.text
    assert "123:secret" not in created.text
    assert created.json()["has_channel_token"] is True

    del payload["channel_token"]
    updated = await client.put(
        f"/api/v1/notifications/rules/{created.json()['id']}", json=payload, headers=headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["has_channel_token"] is True


async def test_someone_elses_rule_is_404(client, login_as, db_session_factory):
    headers, acme, _beta, _hp, _user = await _setup(client, login_as, db_session_factory)
    other = await login_as(
        client, username="other", company_id=acme.id, access_level=AccessLevel.READ
    )
    async with db_session_factory() as db:
        rule = NotificationRule(
            user_id=other.id,
            name="Theirs",
            scope=NotificationScope.COMPANY,
            notify_on_alert=True,
            companies=[await db.get(type(acme), acme.id)],
        )
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
    for method in ("get", "delete"):
        response = await getattr(client, method)(
            f"/api/v1/notifications/rules/{rule.id}", headers=headers
        )
        assert response.status_code == 404


async def test_history_is_own_entries_only(client, login_as, db_session_factory):
    headers, acme, _beta, honeypot, user = await _setup(client, login_as, db_session_factory)
    other = await login_as(
        client, username="other", company_id=acme.id, access_level=AccessLevel.READ
    )
    async with db_session_factory() as db:
        for owner in (user.id, other.id):
            db.add(
                NotificationLog(
                    user_id=owner,
                    honeypot_id=honeypot.id,
                    honeypot_name=honeypot.name,
                    kind=NotificationKind.ALERT,
                    channel=NotificationChannel.EMAIL,
                    target="soc@example.com",
                    success=True,
                )
            )
        await db.commit()
    history = await client.get("/api/v1/notifications/history", headers=headers)
    assert history.status_code == 200
    assert len(history.json()) == 1
    assert history.json()[0]["honeypot_name"] == "acme-honey1"


async def test_alert_types_list_names_ssh_login(client, login_as, db_session_factory):
    headers, *_ = await _setup(client, login_as, db_session_factory)
    types = (await client.get("/api/v1/notifications/alert-types", headers=headers)).json()
    assert {"value": "4002", "label": "SSH login attempt"} in types
