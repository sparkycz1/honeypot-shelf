"""A rule's alert throttle window (`NotificationRule.alert_throttle_minutes`):
at most one alert notification per window and honeypot, the rest counted,
and the next real one saying how many were held back."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.notification_rule_state import NotificationRuleState
from app.db.models.user import User
from app.services.notifications import notify_alert
from tests.conftest import _create_user, create_company

pytestmark = pytest.mark.asyncio


async def _setup(db_session_factory: Any, *, throttle: int | None) -> tuple[Any, Any, Any]:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
    if user is None:  # no `client` fixture in this test, so nobody is logged in yet
        user, _token = await _create_user(db_session_factory, username="owner", is_superadmin=True)
    async with db_session_factory() as db:
        company_row = await db.get(Company, company.id)
        first = Honeypot(companies=[company_row], name="acme-honey1")
        second = Honeypot(companies=[company_row], name="acme-honey2")
        rule = NotificationRule(
            user_id=user.id,
            name="Hook",
            scope=NotificationScope.HONEYPOT,
            honeypots=[first, second],
            delivery_channel=NotificationChannel.WEBHOOK,
            webhook_url="https://hooks.example.com/abc",
            notify_on_alert=True,
            alert_throttle_minutes=throttle,
        )
        db.add_all([first, second, rule])
        await db.commit()
        return rule.id, first.id, second.id


def _capture_webhook(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    posted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook", lambda url, payload: posted.append(payload)
    )
    return posted


async def _alert(db: Any, rule_id: Any, honeypot_id: Any) -> None:
    rule = (
        await db.execute(
            select(NotificationRule)
            .where(NotificationRule.id == rule_id)
            .options(selectinload(NotificationRule.user))
        )
    ).scalar_one()
    honeypot = await db.get(Honeypot, honeypot_id)
    await notify_alert(
        await get_or_create_app_settings(db),
        rules=[rule],
        honeypot=honeypot,
        event_type="4002",
        event_label="SSH login attempt",
        src_ip="203.0.113.7",
        occurred_at=datetime.now(UTC),
        db=db,
    )


async def test_a_burst_sends_one_alert_per_honeypot(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    rule_id, first, second = await _setup(db_session_factory, throttle=30)

    async with db_session_factory() as db:
        for _ in range(5):
            await _alert(db, rule_id, first)
        await _alert(db, rule_id, second)

    assert [p["honeypot_name"] for p in posted] == ["acme-honey1", "acme-honey2"]
    async with db_session_factory() as db:
        logs = (await db.execute(select(NotificationLog))).scalars().all()
        state = (
            await db.execute(
                select(NotificationRuleState).where(NotificationRuleState.honeypot_id == first)
            )
        ).scalar_one()
    # The history holds what was sent, not one row per held-back alert.
    assert len(logs) == 2
    assert state.alerts_held_back == 4


async def test_first_alert_after_the_window_reports_what_was_held_back(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    rule_id, first, _second = await _setup(db_session_factory, throttle=30)

    async with db_session_factory() as db:
        for _ in range(4):
            await _alert(db, rule_id, first)
        await db.execute(
            update(NotificationRuleState).values(
                alert_notified_at=datetime.now(UTC) - timedelta(minutes=45)
            )
        )
        await db.commit()
        await _alert(db, rule_id, first)
        await _alert(db, rule_id, first)

    assert len(posted) == 2
    assert "held_back" not in posted[0]
    assert posted[1]["held_back"] == 3
    async with db_session_factory() as db:
        state = (await db.execute(select(NotificationRuleState))).scalar_one()
    # The count starts again with the new window.
    assert state.alerts_held_back == 1


async def test_rule_without_a_window_sends_every_alert(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture_webhook(monkeypatch)
    rule_id, first, _second = await _setup(db_session_factory, throttle=None)

    async with db_session_factory() as db:
        for _ in range(3):
            await _alert(db, rule_id, first)

    assert len(posted) == 3


async def test_rule_form_saves_the_window(client: Any, db_session_factory: Any) -> None:
    _rule_id, first, _second = await _setup(db_session_factory, throttle=None)
    page = await client.get("/account/notifications")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match
    assert 'name="alert_throttle_minutes"' in page.text
    form = {
        "csrf_token": match.group(1),
        "name": "Throttled",
        "scope": "honeypot",
        "honeypot_ids": str(first),
        "delivery_channel": "webhook",
        "webhook_url": "https://93.184.216.34/hook",
        "notify_on_alert": "on",
    }

    bad = await client.post(
        "/account/notifications", data={**form, "alert_throttle_minutes": "soon"}
    )
    assert "whole number of minutes" in bad.text

    created = await client.post(
        "/account/notifications",
        data={**form, "alert_throttle_minutes": "15"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    async with db_session_factory() as db:
        rule = (
            await db.execute(select(NotificationRule).where(NotificationRule.name == "Throttled"))
        ).scalar_one()
    assert rule.alert_throttle_minutes == 15
