"""`GET /api/v1/events` (+ `/export`) — company-scoped list/export of
HoneypotEvent rows. Was referenced by `auth/account.html`'s API-tokens hint
since that page was written, but never actually existed until now."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _bearer_user_and_events(
    client, login_as, db_session_factory, *, is_superadmin=False
):
    """Creates an API-access-enabled user plus a raw bearer token, and two
    events (one on `company_a`, one on a second, out-of-scope company) —
    used by every test below to check scoping."""
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")

    async with db_session_factory() as db:
        honeypot_a = Honeypot(companies=[company_a], name="acme-honey1")
        honeypot_b = Honeypot(companies=[company_b], name="beta-honey1")
        db.add_all([honeypot_a, honeypot_b])
        await db.commit()
        await db.refresh(honeypot_a)
        await db.refresh(honeypot_b)

        now = datetime.now(UTC)
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot_a.id,
                event_type="4002",
                occurred_at=now - timedelta(minutes=5),
                raw={},
                source="ssh_poll",
            )
        )
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot_b.id,
                event_type="3000",
                occurred_at=now - timedelta(minutes=5),
                raw={},
                source="push",
            )
        )
        await db.commit()

    user = await login_as(
        client,
        username="api-user",
        is_superadmin=is_superadmin,
        company_id=None if is_superadmin else company_a.id,
        access_level=None if is_superadmin else AccessLevel.READ,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        _token, raw_token = await create_api_token(db, db_user, name="test-token", expires_at=None)

    return raw_token, company_a, company_b


async def test_company_scoped_token_only_sees_its_own_companys_events(
    client, login_as, db_session_factory
):
    raw_token, company_a, _company_b = await _bearer_user_and_events(
        client, login_as, db_session_factory
    )

    response = await client.get(
        "/api/v1/events", headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert len(body["events"]) == 1
    assert body["events"][0]["companies"] == [{"id": str(company_a.id), "name": company_a.name}]
    assert body["events"][0]["event_label"] == "SSH login attempt"


async def test_superadmin_token_sees_every_companys_events(client, login_as, db_session_factory):
    raw_token, _company_a, _company_b = await _bearer_user_and_events(
        client, login_as, db_session_factory, is_superadmin=True
    )

    response = await client.get(
        "/api/v1/events", headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert response.status_code == 200
    assert len(response.json()["events"]) == 2


async def test_missing_bearer_token_is_rejected(client):
    response = await client.get("/api/v1/events")
    assert response.status_code == 401


async def test_export_csv_contains_the_scoped_event(client, login_as, db_session_factory):
    raw_token, company_a, _company_b = await _bearer_user_and_events(
        client, login_as, db_session_factory
    )

    response = await client.get(
        "/api/v1/events/export",
        params={"format": "csv"},
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "SSH login attempt" in response.text
    assert company_a.name in response.text


async def test_export_json_format(client, login_as, db_session_factory):
    raw_token, _company_a, _company_b = await _bearer_user_and_events(
        client, login_as, db_session_factory
    )

    response = await client.get(
        "/api/v1/events/export",
        params={"format": "json"},
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    rows = response.json()
    assert len(rows) == 1
    assert rows[0]["event_label"] == "SSH login attempt"


async def test_honeypot_id_filter(client, login_as, db_session_factory):
    raw_token, company_a, _company_b = await _bearer_user_and_events(
        client, login_as, db_session_factory, is_superadmin=True
    )
    async with db_session_factory() as db:
        result = await db.execute(
            select(Honeypot).where(Honeypot.companies.any(Company.id == company_a.id))
        )
        honeypot_a = result.scalar_one()

    response = await client.get(
        "/api/v1/events",
        params={"honeypot_id": str(honeypot_a.id)},
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert response.status_code == 200
    events = response.json()["events"]
    assert len(events) == 1
    assert events[0]["honeypot_id"] == str(honeypot_a.id)
