"""`GET /api` (Swagger UI) — write-tier now, like Scheduling. See
app/web/routes/api_docs.py."""

from __future__ import annotations

import pytest

from app.db.models.user import AccessLevel
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def test_read_only_user_cannot_reach_api_docs(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/api")
    assert response.status_code == 403


async def test_read_write_user_can_reach_api_docs(client, login_as, db_session_factory):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ_WRITE)
    response = await client.get("/api")
    assert response.status_code == 200


async def test_nav_hides_scheduling_and_api_docs_for_a_read_only_user(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert 'href="/scheduling"' not in response.text
    assert 'href="/api"' not in response.text


async def test_nav_shows_scheduling_and_api_docs_for_a_read_write_user(
    client, login_as, db_session_factory
):
    company = await create_company(db_session_factory)
    await login_as(client, company_id=company.id, access_level=AccessLevel.READ_WRITE)
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert 'href="/scheduling"' in response.text
    assert 'href="/api"' in response.text
