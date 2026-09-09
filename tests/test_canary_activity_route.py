"""The honeypot Activity tab (`GET /honeypots/{id}/status`) — same URL as
before (the old, empty "Status" placeholder), now showing what OpenCanary's
log has actually seen. See `app.web.routes.honeypots.honeypot_status_tab`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _create_pinned_honeypot(db_session_factory, company_id) -> Honeypot:
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company_id,
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeyhive",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fake-fingerprint-for-tests",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_activity_tab_shows_not_gathered_yet_placeholder(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/status")

    assert response.status_code == 200
    assert "Not read yet" in response.text


async def test_activity_tab_shows_events_by_human_label(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    now = datetime.now(UTC)
    async with db_session_factory() as db:
        honeypot_row = await db.get(Honeypot, honeypot.id)
        honeypot_row.opencanary_log_polled_at = now
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
                company_id=company.id,
                event_type="4002",
                occurred_at=now - timedelta(minutes=1),
                src_ip="203.0.113.5",
                raw={},
                source="ssh_poll",
            )
        )
        await db.commit()

    response = await client.get(f"/honeypots/{honeypot.id}/status")

    assert response.status_code == 200
    assert "SSH login attempt" in response.text
    assert "203.0.113.5" in response.text


async def test_honeypot_tabs_show_activity_not_a_separate_power_tab(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}")

    assert "Activity" in response.text
    assert "Honeypot status" not in response.text
