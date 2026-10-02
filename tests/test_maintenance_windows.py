"""Maintenance windows — the matching rules (`app.services.
maintenance_windows`), muted notifications, paused scheduled tasks, the
web pages under `/scheduling/maintenance` and the REST API. Ported from
debcontrol, scoped to one company per window."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.auth.api_tokens import create_api_token
from app.core.app_settings import get_or_create_app_settings
from app.db import session as db_session_module
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.notification_log import NotificationChannel, NotificationKind, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import AccessLevel, User
from app.scheduling.jobs import _run_scheduled_task
from app.services import maintenance_windows
from app.services.notifications import notify_alert, notify_unavailable
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio

NOW = datetime.now(UTC)


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def _honeypot(db_session_factory, company: Company, name: str = "hp-1") -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name=name,
            host_key_fingerprint="SHA256:fake",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        return honeypot


async def _window(db_session_factory, company: Company, **kwargs) -> MaintenanceWindow:
    honeypots = kwargs.pop("honeypots", [])
    async with db_session_factory() as db:
        window = MaintenanceWindow(
            owner_company_id=company.id,
            name=kwargs.pop("name", "Patching"),
            starts_at=kwargs.pop("starts_at", NOW - timedelta(hours=1)),
            ends_at=kwargs.pop("ends_at", NOW + timedelta(hours=1)),
            honeypots=[await db.get(Honeypot, h.id) for h in honeypots],
            **kwargs,
        )
        db.add(window)
        await db.commit()
        await db.refresh(window)
        return window


# --- Matching ----------------------------------------------------------------


async def test_all_honeypots_means_only_the_windows_own_company(db_session_factory):
    acme = await create_company(db_session_factory, name="Acme")
    beta = await create_company(db_session_factory, name="Beta")
    acme_hp = await _honeypot(db_session_factory, acme, "acme-hp")
    beta_hp = await _honeypot(db_session_factory, beta, "beta-hp")
    await _window(db_session_factory, acme, all_honeypots=True)

    async with db_session_factory() as db:
        a = await db.get(Honeypot, acme_hp.id)
        b = await db.get(Honeypot, beta_hp.id)
        assert a is not None and b is not None
        assert await maintenance_windows.active_window_for(db, a) is not None
        assert await maintenance_windows.active_window_for(db, b) is None


async def test_alerts_are_muted_only_when_the_window_says_so(db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _honeypot(db_session_factory, company)
    await _window(db_session_factory, company, honeypots=[honeypot])

    async with db_session_factory() as db:
        hp = await db.get(Honeypot, honeypot.id)
        assert hp is not None
        assert await maintenance_windows.muting_window(db, hp, NotificationKind.UNAVAILABLE)
        assert await maintenance_windows.muting_window(db, hp, NotificationKind.RECOVERED)
        assert await maintenance_windows.muting_window(db, hp, NotificationKind.ALERT) is None
        assert await maintenance_windows.muting_window(db, hp, NotificationKind.TEST) is None
        window = (await db.execute(select(MaintenanceWindow))).scalar_one()
        window.mute_alerts = True
        await db.commit()
        assert await maintenance_windows.muting_window(db, hp, NotificationKind.ALERT)


async def test_upcoming_and_ended_windows_do_nothing(db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _honeypot(db_session_factory, company)
    upcoming = await _window(
        db_session_factory,
        company,
        honeypots=[honeypot],
        starts_at=NOW + timedelta(hours=1),
        ends_at=NOW + timedelta(hours=2),
    )
    ended = await _window(
        db_session_factory,
        company,
        honeypots=[honeypot],
        starts_at=NOW - timedelta(hours=2),
        ends_at=NOW - timedelta(hours=1),
    )
    assert maintenance_windows.window_state(upcoming) == "upcoming"
    assert maintenance_windows.window_state(ended) == "ended"
    async with db_session_factory() as db:
        hp = await db.get(Honeypot, honeypot.id)
        assert hp is not None
        assert await maintenance_windows.active_window_for(db, hp) is None


# --- Notifications and scheduled tasks -----------------------------------------


async def _webhook_rule(db_session_factory, honeypot: Honeypot) -> NotificationRule:
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        if user is None:
            from app.db.models.user import AuthProvider

            user = User(username="owner", auth_provider=AuthProvider.LOCAL, is_active=True)
            db.add(user)
            await db.flush()
        rule = NotificationRule(
            user_id=user.id,
            name="Hook",
            scope=NotificationScope.HONEYPOT,
            honeypots=[await db.get(Honeypot, honeypot.id)],
            delivery_channel=NotificationChannel.WEBHOOK,
            webhook_url="https://hooks.example.com/services/secret",
            notify_on_alert=True,
            notify_on_unavailable=True,
        )
        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        return rule


async def test_unavailable_is_muted_and_logged_but_alert_still_goes_out(
    db_session_factory, monkeypatch
):
    company = await create_company(db_session_factory)
    honeypot = await _honeypot(db_session_factory, company)
    await _window(db_session_factory, company, name="Re-flash", all_honeypots=True)
    rule = await _webhook_rule(db_session_factory, honeypot)
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        "app.services.notifications.send_webhook", lambda url, payload: sent.append(payload)
    )

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        hp = await db.get(Honeypot, honeypot.id)
        db_rule = (
            await db.execute(
                select(NotificationRule)
                .options(selectinload(NotificationRule.user))
                .where(NotificationRule.id == rule.id)
            )
        ).scalar_one()
        assert hp is not None and db_rule is not None
        await notify_unavailable(
            app_settings, rule=db_rule, honeypot=hp, threshold_minutes=10, db=db
        )
        await notify_alert(
            app_settings,
            rules=[db_rule],
            honeypot=hp,
            event_type="ssh.login_attempt",
            event_label="SSH login attempt",
            src_ip="203.0.113.9",
            occurred_at=NOW,
            db=db,
        )
        entries = (
            (await db.execute(select(NotificationLog).order_by(NotificationLog.created_at)))
            .scalars()
            .all()
        )

    assert [p["kind"] for p in sent] == ["alert"]
    muted = [e for e in entries if e.muted_by]
    assert len(muted) == 1
    assert muted[0].kind == NotificationKind.UNAVAILABLE
    assert muted[0].muted_by == "Re-flash"
    assert muted[0].target == "https://hooks.example.com/…"


async def test_scheduled_task_skips_paused_honeypots(db_session_factory, monkeypatch, celery_calls):
    monkeypatch.setattr(db_session_module, "AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    paused = await _honeypot(db_session_factory, company, "paused-hp")
    await _honeypot(db_session_factory, company, "running-hp")
    await _window(db_session_factory, company, honeypots=[paused], pause_scheduled_tasks=True)
    async with db_session_factory() as db:
        task = ScheduledTask(
            name="Nightly check",
            action="check_updates",
            target_type="all_honeypots",
            owner_company_id=company.id,
            cron_expression="0 3 * * *",
        )
        db.add(task)
        await db.commit()
        await db.refresh(task)

    result = await _run_scheduled_task(str(task.id))

    assert result["ok"] is True
    assert result["attempted"] == 1
    assert result["paused_by_maintenance"] == 1
    enqueued = [c[1][0] for c in celery_calls if c[0] == "app.tasks.jobs.check_honeypot_updates"]
    assert str(paused.id) not in enqueued
    async with db_session_factory() as db:
        stored = await db.get(ScheduledTask, task.id)
        assert stored is not None
        assert "1 paused by a maintenance window" in (stored.last_run_summary or "")


# --- Web pages ------------------------------------------------------------------


async def test_create_list_end_and_delete_through_the_web(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _honeypot(db_session_factory, company)
    form = await client.get("/scheduling/maintenance/new")
    assert form.status_code == 200

    response = await client.post(
        "/scheduling/maintenance",
        data={
            "csrf_token": _csrf_from(form),
            "owner_company_id": str(company.id),
            "name": "Re-flash",
            "starts_at": (NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M"),
            "ends_at": (NOW + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
            "honeypot_ids": str(honeypot.id),
            "pause_scheduled_tasks": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        window = (await db.execute(select(MaintenanceWindow))).scalar_one()
        assert window.pause_scheduled_tasks and not window.mute_alerts
        assert [h.id for h in window.honeypots] == [honeypot.id]
        assert window.created_by is not None

    listing = await client.get("/scheduling/maintenance")
    assert "Re-flash" in listing.text
    detail = await client.get(f"/honeypots/{honeypot.id}")
    assert "In maintenance until" in detail.text

    await client.post(
        f"/scheduling/maintenance/{window.id}/end",
        data={"csrf_token": _csrf_from(listing)},
        follow_redirects=False,
    )
    async with db_session_factory() as db:
        ended = await db.get(MaintenanceWindow, window.id)
        assert ended is not None
        assert maintenance_windows.window_state(ended) == "ended"

    await client.post(
        f"/scheduling/maintenance/{window.id}/delete",
        data={"csrf_token": _csrf_from(listing)},
        follow_redirects=False,
    )
    async with db_session_factory() as db:
        assert (await db.execute(select(MaintenanceWindow))).scalar_one_or_none() is None


async def test_form_errors_are_shown_and_nothing_is_saved(client, db_session_factory):
    company = await create_company(db_session_factory)
    form = await client.get("/scheduling/maintenance/new")
    response = await client.post(
        "/scheduling/maintenance",
        data={
            "csrf_token": _csrf_from(form),
            "owner_company_id": str(company.id),
            "name": "Backwards",
            "starts_at": "2026-10-02T12:00",
            "ends_at": "2026-10-02T11:00",
            "all_honeypots": "on",
        },
    )
    assert response.status_code == 200
    assert "The window must end after it starts." in response.text
    async with db_session_factory() as db:
        assert (await db.execute(select(MaintenanceWindow))).scalar_one_or_none() is None


async def test_company_user_sees_and_manages_only_their_own_windows(
    client, db_session_factory, login_as
):
    acme = await create_company(db_session_factory, name="Acme")
    beta = await create_company(db_session_factory, name="Beta")
    await _window(db_session_factory, acme, name="Acme work", all_honeypots=True)
    beta_window = await _window(db_session_factory, beta, name="Beta work", all_honeypots=True)
    await login_as(client, company_id=acme.id, access_level=AccessLevel.READ_WRITE)

    listing = await client.get("/scheduling/maintenance")
    assert "Acme work" in listing.text and "Beta work" not in listing.text
    edit = await client.get(f"/scheduling/maintenance/{beta_window.id}/edit")
    assert edit.status_code == 404

    form = await client.get("/scheduling/maintenance/new")
    response = await client.post(
        "/scheduling/maintenance",
        data={
            "csrf_token": _csrf_from(form),
            "owner_company_id": str(beta.id),
            "name": "Sneaky",
            "starts_at": "2026-10-02T10:00",
            "ends_at": "2026-10-02T11:00",
            "all_honeypots": "on",
        },
    )
    assert response.status_code == 200
    assert "Pick a company you can manage." in response.text


async def test_read_only_user_cannot_reach_maintenance(client, db_session_factory, login_as):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    assert (await client.get("/scheduling/maintenance")).status_code == 403


async def test_history_shows_channel_names_and_muted_entries(client, db_session_factory):
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        db.add(
            NotificationLog(
                user_id=user.id,
                kind=NotificationKind.UNAVAILABLE,
                channel=NotificationChannel.EMAIL,
                target="ops@example.com",
                success=False,
                muted_by="Re-flash",
            )
        )
        await db.commit()

    page = await client.get("/account/notifications/history")
    assert "notifications.subscriptions.channel_" not in page.text
    assert ">Email<" in page.text
    assert "Muted (Re-flash)" in page.text


# --- REST API -------------------------------------------------------------------


async def _bearer(db_session_factory) -> dict[str, str]:
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        _token, raw = await create_api_token(db, user, name="t", expires_at=None)
        await db.commit()
    return {"Authorization": f"Bearer {raw}"}


async def test_api_create_list_end_and_delete(client, db_session_factory):
    company = await create_company(db_session_factory)
    headers = await _bearer(db_session_factory)

    created = await client.post(
        "/api/v1/maintenance-windows",
        headers=headers,
        json={
            "owner_company_id": str(company.id),
            "name": "API window",
            "starts_at": (NOW - timedelta(minutes=1)).isoformat(),
            "ends_at": (NOW + timedelta(hours=1)).isoformat(),
            "all_honeypots": True,
            "mute_alerts": True,
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["state"] == "active" and body["mute_alerts"] is True

    listed = await client.get("/api/v1/maintenance-windows", headers=headers)
    assert [w["name"] for w in listed.json()] == ["API window"]

    ended = await client.post(f"/api/v1/maintenance-windows/{body['id']}/end", headers=headers)
    assert ended.json()["state"] == "ended"

    deleted = await client.delete(f"/api/v1/maintenance-windows/{body['id']}", headers=headers)
    assert deleted.status_code == 204
    missing = await client.get(f"/api/v1/maintenance-windows/{uuid.uuid4()}", headers=headers)
    assert missing.status_code == 404


async def test_api_rejects_an_invalid_window(client, db_session_factory):
    company = await create_company(db_session_factory)
    headers = await _bearer(db_session_factory)
    response = await client.post(
        "/api/v1/maintenance-windows",
        headers=headers,
        json={
            "owner_company_id": str(company.id),
            "name": "No scope",
            "starts_at": NOW.isoformat(),
            "ends_at": (NOW + timedelta(hours=1)).isoformat(),
        },
    )
    assert response.status_code == 422
