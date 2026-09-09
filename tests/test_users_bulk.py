"""Bulk actions on the Users list: select several users, then delete or
re-assign them to a company/access level in one go. Mirrors the honeypots
list's own bulk-select pattern (checkbox column, `data-select-all`,
`bulk-select.js` — see also that page's own regression, fixed alongside
this: the shared script used to hardcode `machine_ids`, a debcontrol
leftover, so "select all" silently did nothing on the Honeypots page)."""

from __future__ import annotations

import re

import pytest

from app.db.models.user import AccessLevel, AuthProvider, User
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_bulk_select_all_toggles_the_users_checkbox_name(client):
    response = await client.get("/users")
    assert 'data-select-all="user_ids"' in response.text


async def test_bulk_delete_deletes_selected_users_and_skips_self(
    client, db_session_factory, login_as
):
    company = await create_company(db_session_factory)
    victim = await login_as(
        client, username="victim", company_id=company.id, access_level=AccessLevel.READ
    )
    admin = await login_as(client, username="the-admin", is_superadmin=True)

    page = await client.get("/users")
    csrf_token = _csrf_from(page)

    response = await client.post(
        "/users/bulk/delete",
        data={"user_ids": [str(victim.id), str(admin.id)], "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "bulk_deleted=1" in response.headers["location"]
    assert "bulk_skipped=1" in response.headers["location"]

    async with db_session_factory() as db:
        assert await db.get(User, victim.id) is None
        assert await db.get(User, admin.id) is not None  # skipped: own account


async def test_would_remove_last_superadmin_is_reused_by_the_bulk_route(db_session_factory):
    """The bulk route reuses the exact same `_would_remove_last_superadmin`
    helper the single-user delete route already relies on — a direct check
    of that shared helper, since reaching the "last superadmin" branch over
    HTTP needs the acting account itself to not count as the superadmin
    left standing, which `require_superadmin` never allows: the only
    active superadmin left standing per selected target is always at
    least the one making the request."""
    from app.web.routes.users import _would_remove_last_superadmin

    async with db_session_factory() as db:
        solo_admin = User(
            username="solo-admin",
            is_superadmin=True,
            is_active=True,
            auth_provider=AuthProvider.LOCAL,
        )
        db.add(solo_admin)
        await db.commit()
        await db.refresh(solo_admin)
        assert await _would_remove_last_superadmin(db, solo_admin) is True

        other_admin = User(
            username="second-admin",
            is_superadmin=True,
            is_active=True,
            auth_provider=AuthProvider.LOCAL,
        )
        db.add(other_admin)
        await db.commit()
        assert await _would_remove_last_superadmin(db, solo_admin) is False


async def test_bulk_assign_company_reassigns_and_skips_superadmins(
    client, db_session_factory, login_as
):
    company_a = await create_company(db_session_factory, name="Acme")
    company_b = await create_company(db_session_factory, name="Beta")
    plain_user = await login_as(
        client, username="plain", company_id=company_a.id, access_level=AccessLevel.READ
    )
    superadmin = await login_as(client, username="an-admin", is_superadmin=True)
    await login_as(client, username="acting-admin", is_superadmin=True)

    page = await client.get("/users")
    csrf_token = _csrf_from(page)

    response = await client.post(
        "/users/bulk/assign-company",
        data={
            "user_ids": [str(plain_user.id), str(superadmin.id)],
            "company_id": str(company_b.id),
            "access_level": AccessLevel.READ_WRITE.value,
            "csrf_token": csrf_token,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "bulk_assigned=1" in response.headers["location"]
    assert "bulk_skipped=1" in response.headers["location"]

    async with db_session_factory() as db:
        updated = await db.get(User, plain_user.id)
        assert updated.company_id == company_b.id
        assert updated.access_level == AccessLevel.READ_WRITE
        untouched = await db.get(User, superadmin.id)
        assert untouched.is_superadmin is True


async def test_bulk_delete_with_no_selection_shows_an_error(client, login_as):
    await login_as(client, is_superadmin=True)
    page = await client.get("/users")
    csrf_token = _csrf_from(page)
    response = await client.post(
        "/users/bulk/delete", data={"csrf_token": csrf_token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "bulk_error=" in response.headers["location"]
