"""Company CRUD — superadmin-only. Deleting a company cascades to delete
its honeypots (no "orphan the honeypots" option here, unlike debcontrol's
optional machine-group membership — see app/web/routes/companies.py)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_create_company(client):
    new_form = await client.get("/companies/new")
    response = await client.post(
        "/companies",
        data={"name": "Acme Corp", "notes": "Test", "csrf_token": _csrf_from(new_form)},
    )
    assert response.status_code == 303


async def test_deleting_a_company_deletes_its_honeypots(client, db_session_factory):
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        db.add(Honeypot(company_id=company.id, name="acme-honey1"))
        await db.commit()
        await db.refresh(company)

    detail = await client.get(f"/companies/{company.id}")
    response = await client.post(
        f"/companies/{company.id}/delete", data={"csrf_token": _csrf_from(detail)}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await db.get(Company, company.id) is None
        result = await db.execute(select(Honeypot))
        assert result.scalars().all() == []
