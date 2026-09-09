"""`GET /honeypots/{id}/status/export` — the Activity tab's CSV/JSON
download link (session-authenticated, unlike `/api/v1/events/export`)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _create_pinned_honeypot_with_events(db_session_factory, company_id) -> Honeypot:
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

        now = datetime.now(UTC)
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
                company_id=company_id,
                event_type="4002",
                occurred_at=now - timedelta(days=10),
                raw={},
                source="ssh_poll",
            )
        )
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
                company_id=company_id,
                event_type="3000",
                occurred_at=now - timedelta(minutes=5),
                raw={},
                source="push",
            )
        )
        await db.commit()
    return honeypot


async def test_export_csv_includes_all_events_when_no_range_given(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot_with_events(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/status/export?format=csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "SSH login attempt" in response.text
    assert "HTTP GET request" in response.text


async def test_export_respects_range_key_filter(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot_with_events(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/status/export?format=csv&range_key=1h")

    assert response.status_code == 200
    # The 10-day-old event falls outside "last hour".
    assert "SSH login attempt" not in response.text
    assert "HTTP GET request" in response.text


async def test_export_json_format(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_pinned_honeypot_with_events(db_session_factory, company.id)

    response = await client.get(f"/honeypots/{honeypot.id}/status/export?format=json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    rows = response.json()
    assert len(rows) == 2
