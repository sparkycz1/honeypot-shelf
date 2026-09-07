"""Honeypot CRUD and company scoping on the list/detail pages."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.honeypot import Honeypot
from app.db.models.user import AccessLevel
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def test_superadmin_can_create_a_honeypot(client, db_session_factory):
    company = await create_company(db_session_factory)
    new_form = await client.get("/honeypots/new")
    assert new_form.status_code == 200

    response = await client.post(
        "/honeypots",
        data={
            "name": "acme-honey1",
            "ip_address": "10.0.0.5",
            "port": "22",
            "username": "pi",
            "auth_method": "ssh_key",
            "company_id": str(company.id),
            "location": "Server room",
            "csrf_token": _csrf_from(new_form),
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        result = await db.execute(select(Honeypot))
        honeypots = result.scalars().all()
        assert len(honeypots) == 1
        assert honeypots[0].name == "acme-honey1"
        assert honeypots[0].company_id == company.id


async def test_company_user_only_sees_own_companys_honeypots(
    client, db_session_factory, login_as
):
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    async with db_session_factory() as db:
        db.add(Honeypot(company_id=company_a.id, name="acme-honey1"))
        db.add(Honeypot(company_id=company_b.id, name="beta-honey1"))
        await db.commit()

    await login_as(
        client, is_superadmin=False, company_id=company_a.id, access_level=AccessLevel.READ
    )
    response = await client.get("/honeypots")
    assert response.status_code == 200
    assert "acme-honey1" in response.text
    assert "beta-honey1" not in response.text


async def test_honeypot_detail_404s_for_out_of_scope_company(
    client, db_session_factory, login_as
):
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    async with db_session_factory() as db:
        honeypot = Honeypot(company_id=company_b.id, name="beta-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)

    await login_as(
        client, is_superadmin=False, company_id=company_a.id, access_level=AccessLevel.READ_WRITE
    )
    response = await client.get(f"/honeypots/{honeypot.id}")
    assert response.status_code == 404


def _csrf_from(response) -> str:
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)
