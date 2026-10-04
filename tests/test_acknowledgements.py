"""Acknowledging a problem on a honeypot (`app.services.acknowledgements`):
what it withholds, what ends it, and the web and REST routes around it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.auth.api_tokens import create_api_token
from app.core.app_settings import get_or_create_app_settings
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from app.services import acknowledgements
from app.services.notifications import notify_alert, notify_recovered, notify_unavailable
from tests.conftest import _create_user, create_company


async def _honeypot(db_session_factory: Any, name: str = "acme-honey1") -> Any:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name=name)
        db.add(honeypot)
        await db.commit()
        return honeypot.id, company.id


async def _rule(db_session_factory: Any, honeypot_id: Any) -> Any:
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
    if user is None:
        user, _token = await _create_user(db_session_factory, username="owner", is_superadmin=True)
    async with db_session_factory() as db:
        rule = NotificationRule(
            user_id=user.id,
            name="Hook",
            scope=NotificationScope.HONEYPOT,
            honeypots=[await db.get(Honeypot, honeypot_id)],
            delivery_channel=NotificationChannel.WEBHOOK,
            webhook_url="https://hooks.example.com/abc",
        )
        db.add(rule)
        await db.commit()
        return rule.id


def test_an_acknowledgement_is_active_until_its_end_time() -> None:
    honeypot = Honeypot(name="h")
    now = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    assert not acknowledgements.is_active(honeypot, now)

    acknowledgements.acknowledge(honeypot, by="alice", note=" known scan ", hours=8, now=now)
    assert honeypot.acknowledged_note == "known scan"
    assert acknowledgements.is_active(honeypot, now + timedelta(hours=7))
    assert not acknowledgements.is_active(honeypot, now + timedelta(hours=8))

    acknowledgements.acknowledge(honeypot, by="alice", note=None, hours=None, now=now)
    assert acknowledgements.is_active(honeypot, now + timedelta(days=400))
    acknowledgements.clear(honeypot)
    assert not acknowledgements.is_active(honeypot, now)
    with pytest.raises(ValueError):
        acknowledgements.acknowledge(honeypot, by="alice", note=None, hours=0)
    with pytest.raises(ValueError):
        acknowledgements.hours_for("forever")


async def test_acknowledged_honeypot_withholds_alerts_and_outage_but_not_recovery(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[str] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook",
        lambda url, payload: posted.append(payload["kind"]),
    )
    honeypot_id, _company = await _honeypot(db_session_factory)
    rule_id = await _rule(db_session_factory, honeypot_id)

    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        rule = (
            await db.execute(
                select(NotificationRule)
                .where(NotificationRule.id == rule_id)
                .options(selectinload(NotificationRule.user))
            )
        ).scalar_one()
        app_settings = await get_or_create_app_settings(db)
        acknowledgements.acknowledge(honeypot, by="alice", note="known", hours=None)
        await db.commit()

        await notify_alert(
            app_settings,
            rules=[rule],
            honeypot=honeypot,
            event_type="4002",
            event_label="SSH login attempt",
            src_ip="203.0.113.7",
            occurred_at=datetime.now(UTC),
            db=db,
        )
        await notify_unavailable(
            app_settings, rule=rule, honeypot=honeypot, threshold_minutes=10, db=db
        )
        await notify_recovered(
            app_settings, rule=rule, honeypot=honeypot, threshold_minutes=5, db=db
        )
        logs = (await db.execute(select(NotificationLog))).scalars().all()

    assert posted == ["recovered"]
    muted = [log.muted_by for log in logs if log.muted_by]
    assert muted == ["acknowledged by alice", "acknowledged by alice"]


async def test_web_acknowledge_and_clear(client: Any, db_session_factory: Any) -> None:
    honeypot_id, _company = await _honeypot(db_session_factory)

    page = await client.get(f"/honeypots/{honeypot_id}")
    assert f'action="/honeypots/{honeypot_id}/acknowledge"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    bad = await client.post(
        f"/honeypots/{honeypot_id}/acknowledge", data={**csrf, "duration": "forever"}
    )
    assert bad.status_code == 422
    done = await client.post(
        f"/honeypots/{honeypot_id}/acknowledge",
        data={**csrf, "duration": "8h", "note": "known scan"},
        follow_redirects=False,
    )
    assert done.status_code == 303

    page = await client.get(f"/honeypots/{honeypot_id}")
    assert "known scan" in page.text
    assert f'action="/honeypots/{honeypot_id}/acknowledge/clear"' in page.text
    assert "acknowledged" in (await client.get("/honeypots")).text

    cleared = await client.post(
        f"/honeypots/{honeypot_id}/acknowledge/clear", data=csrf, follow_redirects=False
    )
    assert cleared.status_code == 303
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and honeypot.acknowledged_at is None


async def test_a_read_only_account_cannot_acknowledge(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    honeypot_id, company_id = await _honeypot(db_session_factory)
    await login_as(
        client, username="reader", company_id=company_id, access_level=AccessLevel.READ
    )
    page = await client.get(f"/honeypots/{honeypot_id}")
    assert f'action="/honeypots/{honeypot_id}/acknowledge"' not in page.text
    response = await client.post(
        f"/honeypots/{honeypot_id}/acknowledge",
        data={"csrf_token": client.cookies.get("csrftoken"), "duration": "8h"},
        follow_redirects=False,
    )
    assert response.status_code in (303, 403)
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and honeypot.acknowledged_at is None


async def test_api_acknowledge(client: Any, login_as: Any, db_session_factory: Any) -> None:
    honeypot_id, _company = await _honeypot(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw_token}"}
    base = f"/api/v1/honeypots/{honeypot_id}"

    too_long = await client.post(f"{base}/acknowledge", json={"hours": 100000}, headers=headers)
    assert too_long.status_code == 422
    done = await client.post(
        f"{base}/acknowledge", json={"hours": 4, "note": "known"}, headers=headers
    )
    assert done.status_code == 200
    body = done.json()["acknowledgement"]
    assert body["note"] == "known" and body["until"] is not None and body["by"] == "api-admin"

    shown = (await client.get(base, headers=headers)).json()
    assert shown["acknowledgement"]["note"] == "known"
    cleared = await client.delete(f"{base}/acknowledge", headers=headers)
    assert cleared.status_code == 204
    shown = (await client.get(base, headers=headers)).json()
    assert shown["acknowledgement"] is None
