"""How long OpenCanary events are kept can be set in Settings → Checks &
retention; until it is, `EVENT_RETENTION_DAYS` from `.env` applies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.core.app_settings import effective_event_retention_days, get_or_create_app_settings
from app.core.config import get_settings
from app.db.models.app_settings import AppSettings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.tasks import jobs
from tests.conftest import create_company


def test_settings_value_wins_over_the_env_default() -> None:
    default = get_settings().event_retention_days
    assert effective_event_retention_days(AppSettings()) == default
    assert effective_event_retention_days(AppSettings(event_retention_days=7)) == 7


async def test_purge_uses_the_value_from_settings(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        await db.flush()
        for days_ago in (1, 10, 40):
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type="4002",
                    occurred_at=now - timedelta(days=days_ago),
                    raw={},
                )
            )
        (await get_or_create_app_settings(db)).event_retention_days = 30
        await db.commit()

    await jobs._purge_old_events()
    async with db_session_factory() as db:
        left = (await db.execute(select(HoneypotEvent))).scalars().all()
        assert len(left) == 2
        (await get_or_create_app_settings(db)).event_retention_days = 5
        await db.commit()

    await jobs._purge_old_events()
    async with db_session_factory() as db:
        assert len((await db.execute(select(HoneypotEvent))).scalars().all()) == 1


async def test_settings_form_saves_validates_and_resets(
    client: Any, db_session_factory: Any
) -> None:
    page = await client.get("/settings?tab=checks")
    assert 'action="/settings/event-retention"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    for bad in ("0", "99999", "soon"):
        refused = await client.post(
            "/settings/event-retention", data={**csrf, "retention_days": bad}
        )
        assert "days" in refused.text
    saved = await client.post(
        "/settings/event-retention", data={**csrf, "retention_days": "30"}, follow_redirects=False
    )
    assert saved.status_code == 303
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).event_retention_days == 30

    reset = await client.post(
        "/settings/event-retention", data={**csrf, "retention_days": ""}, follow_redirects=False
    )
    assert reset.status_code == 303
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).event_retention_days is None
