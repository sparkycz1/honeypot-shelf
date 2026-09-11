"""The Dashboard — every user sees the sum across their own company's
honeypots/events; a superadmin additionally sees a per-company breakdown."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _add_honeypot_with_event(db_session_factory, company_id, name="honey1"):
    async with db_session_factory() as db:
        company = await db.get(Company, company_id)
        honeypot = Honeypot(companies=[company], name=name, last_seen_at=datetime.now(UTC))
        db.add(honeypot)
        await db.flush()
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
                event_type="SSH_LOGIN_ATTEMPT",
                occurred_at=datetime.now(UTC),
                raw={},
            )
        )
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def test_dashboard_shows_fleet_wide_activity_by_type(client, db_session_factory):
    """Same per-type bucketing the honeypot Activity tab uses
    (`app.services.canary_activity_history`), fed events across every
    honeypot in scope instead of one — see `app/web/routes/dashboard.py`."""
    company = await create_company(db_session_factory, name="Acme")
    honeypot = await _add_honeypot_with_event(db_session_factory, company.id, "acme1")
    async with db_session_factory() as db:
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
event_type="4002",
                occurred_at=datetime.now(UTC),
                raw={},
            )
        )
        await db.commit()

    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "SSH login attempt" in response.text


async def test_dashboard_shows_totals_across_companies_for_superadmin(client, db_session_factory):
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    await _add_honeypot_with_event(db_session_factory, company_a.id, "acme1")
    await _add_honeypot_with_event(db_session_factory, company_b.id, "beta1")

    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Acme" in response.text
    assert "Beta" in response.text


async def test_dashboard_scopes_to_own_company_for_a_company_user(
    client, db_session_factory, login_as
):
    from app.db.models.user import AccessLevel

    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    await _add_honeypot_with_event(db_session_factory, company_a.id, "acme1")
    await _add_honeypot_with_event(db_session_factory, company_b.id, "beta1")

    await login_as(
        client, is_superadmin=False, company_id=company_a.id, access_level=AccessLevel.READ
    )
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Beta" not in response.text
