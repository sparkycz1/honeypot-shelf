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


async def test_package_search_with_a_query_does_not_crash(client, db_session_factory):
    """Regression test — `honeypots_visible_to()` is a plain sync function
    returning a `Select`, not a coroutine (see its own docstring); a stray
    `await` in front of it made this endpoint raise a TypeError on every
    search with a non-empty query. Caught by mypy, not by any prior test."""
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(company_id=company.id, name="acme-honey1")
        db.add(honeypot)
        await db.commit()

    response = await client.get("/honeypots/package-search", params={"q": "openssl"})
    assert response.status_code == 200


async def test_list_select_all_checkbox_names_the_honeypot_checkboxes(client, db_session_factory):
    """Regression guard: `bulk-select.js` used to hardcode toggling
    checkboxes named `machine_ids` (a debcontrol leftover) — honeypot
    checkboxes are named `honeypot_ids`, so "select all" silently did
    nothing on this page. Fixed by having the "select all" checkbox name
    its own target via `data-select-all="honeypot_ids"`."""
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        db.add(Honeypot(company_id=company.id, name="acme-honey1"))
        await db.commit()

    response = await client.get("/honeypots")
    assert response.status_code == 200
    assert 'data-select-all="honeypot_ids"' in response.text


async def test_ingest_token_rotate_and_revoke(client, db_session_factory):
    """Generating a token shows the raw value exactly once and stores only
    its hash; revoking clears it. See `app.auth.ingest_tokens`."""
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(company_id=company.id, name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        honeypot_id = honeypot.id

    edit_page = await client.get(f"/honeypots/{honeypot_id}/edit")
    assert 'name="csrf_token"' in edit_page.text

    rotate = await client.post(
        f"/honeypots/{honeypot_id}/ingest-token/rotate",
        data={"csrf_token": _csrf_from(edit_page)},
    )
    assert rotate.status_code == 200
    assert "hhit_" in rotate.text

    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot.ingest_token_hash is not None
        first_hash = honeypot.ingest_token_hash

    # Rotating again overwrites the previous hash.
    rotate_again = await client.post(
        f"/honeypots/{honeypot_id}/ingest-token/rotate",
        data={"csrf_token": _csrf_from(edit_page)},
    )
    assert rotate_again.status_code == 200
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot.ingest_token_hash != first_hash

    revoke = await client.post(
        f"/honeypots/{honeypot_id}/ingest-token/revoke",
        data={"csrf_token": _csrf_from(edit_page)},
        follow_redirects=False,
    )
    assert revoke.status_code == 303
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot.ingest_token_hash is None


async def test_bulk_delete_honeypots(client, db_session_factory):
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot_a = Honeypot(company_id=company.id, name="acme-honey1")
        honeypot_b = Honeypot(company_id=company.id, name="acme-honey2")
        db.add_all([honeypot_a, honeypot_b])
        await db.commit()
        await db.refresh(honeypot_a)
        await db.refresh(honeypot_b)
        honeypot_a_id, honeypot_b_id = honeypot_a.id, honeypot_b.id

    list_page = await client.get("/honeypots")
    response = await client.post(
        "/honeypots/bulk/delete",
        data={
            "honeypot_ids": [str(honeypot_a_id), str(honeypot_b_id)],
            "csrf_token": _csrf_from(list_page),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        assert await db.get(Honeypot, honeypot_a_id) is None
        assert await db.get(Honeypot, honeypot_b_id) is None


async def test_bulk_delete_honeypots_with_no_selection_shows_an_error(client):
    list_page = await client.get("/honeypots")
    response = await client.post(
        "/honeypots/bulk/delete",
        data={"csrf_token": _csrf_from(list_page)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "bulk_error" in response.headers["location"]
