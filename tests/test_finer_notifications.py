"""Finer notification rules: an alert can be limited to chosen event
types, and a rule can announce the honeypot's own health (disk about to
fill, a failed service, a pending reboot) — each once, when it appears."""

from __future__ import annotations

import re
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from app.services import acknowledgements
from app.tasks import jobs
from tests.conftest import _create_user, create_company


def test_a_rule_without_a_type_filter_wants_every_alert() -> None:
    rule = NotificationRule(name="r")
    assert rule.wants_alert("4002") and rule.wants_alert("3000")
    rule.alert_event_types = ["4002"]
    assert rule.wants_alert("4002") and not rule.wants_alert("3000")
    rule.alert_event_types = []
    assert rule.wants_alert("3000")


async def _setup(db_session_factory: Any, **flags: bool) -> Any:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
    if user is None:
        user, _token = await _create_user(db_session_factory, username="owner", is_superadmin=True)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        db.add(
            NotificationRule(
                user_id=user.id,
                name="Health",
                scope=NotificationScope.HONEYPOT,
                honeypots=[honeypot],
                delivery_channel=NotificationChannel.WEBHOOK,
                webhook_url="https://hooks.example.com/abc",
                notify_on_alert=False,
                notify_on_unavailable=False,
                notify_on_recovered=False,
                **flags,
            )
        )
        await db.commit()
        return honeypot.id


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    posted: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook",
        lambda url, payload: posted.append((payload["kind"], payload.get("details", ""))),
    )
    return posted


async def _announce(db_session_factory: Any, honeypot_id: Any, current: list[str]) -> None:
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        await jobs._announce_health(
            db,
            honeypot,
            kind=NotificationKind.SERVICE_FAILED,
            rule_column=NotificationRule.notify_on_service_failed,
            current=current,
        )


async def test_a_problem_is_announced_once_and_again_after_it_came_back(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture(monkeypatch)
    honeypot_id = await _setup(db_session_factory, notify_on_service_failed=True)

    await _announce(db_session_factory, honeypot_id, ["a.service"])
    await _announce(db_session_factory, honeypot_id, ["a.service"])
    await _announce(db_session_factory, honeypot_id, ["a.service", "b.service"])
    await _announce(db_session_factory, honeypot_id, [])
    await _announce(db_session_factory, honeypot_id, ["a.service"])

    assert posted == [
        ("service_failed", "a.service"),
        ("service_failed", "b.service"),
        ("service_failed", "a.service"),
    ]
    async with db_session_factory() as db:
        kinds = (await db.execute(select(NotificationLog.kind))).scalars().all()
    assert set(kinds) == {NotificationKind.SERVICE_FAILED}


async def test_a_rule_that_did_not_ask_gets_nothing(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture(monkeypatch)
    honeypot_id = await _setup(db_session_factory, notify_on_disk_full=True)
    await _announce(db_session_factory, honeypot_id, ["a.service"])
    assert posted == []


async def test_an_acknowledged_honeypot_keeps_health_problems_quiet(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted = _capture(monkeypatch)
    honeypot_id = await _setup(db_session_factory, notify_on_service_failed=True)
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        acknowledgements.acknowledge(honeypot, by="alice", note=None, hours=None)
        await db.commit()

    await _announce(db_session_factory, honeypot_id, ["a.service"])
    assert posted == []
    async with db_session_factory() as db:
        log = (await db.execute(select(NotificationLog))).scalar_one()
    assert log.muted_by == "acknowledged by alice"


async def test_rule_form_saves_the_type_filter_and_health_switches(
    client: Any, db_session_factory: Any
) -> None:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        honeypot_id = honeypot.id

    page = await client.get("/account/notifications")
    assert 'name="alert_event_types"' in page.text and 'name="notify_on_disk_full"' in page.text
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match
    created = await client.post(
        "/account/notifications",
        data={
            "csrf_token": match.group(1),
            "name": "Picky",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "webhook",
            "webhook_url": "https://93.184.216.34/hook",
            "notify_on_alert": "on",
            "alert_event_types": ["4002", "not-a-type"],
            "notify_on_reboot_required": "on",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
    assert rule.alert_event_types == ["4002"]
    assert rule.notify_on_reboot_required and not rule.notify_on_disk_full

    # A rule with only a health switch is a valid rule.
    only_health = await client.post(
        "/account/notifications",
        data={
            "csrf_token": match.group(1),
            "name": "Disks",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "webhook",
            "webhook_url": "https://93.184.216.34/hook",
            "notify_on_disk_full": "on",
        },
        follow_redirects=False,
    )
    assert only_health.status_code == 303
