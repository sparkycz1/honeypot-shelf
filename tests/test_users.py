"""User CRUD edge cases not covered elsewhere — ported from an identical
fix in debcontrol (`a09d605`): editing a user to a duplicate username used
to crash instead of returning a clean 409 — see
`tests/conftest.py`'s `db_session_factory` docstring for the aiosqlite
quirk this guards against, and `app.web.routes.users._duplicate_username_error`
for the fix."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.user import AuthProvider, User
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_edit_user_to_a_duplicate_username_is_rejected(client, db_session_factory):
    company = await create_company(db_session_factory)

    new_form = await client.get("/users/new")
    await client.post(
        "/users",
        data={
            "username": "taken-name",
            "display_name": "Taken",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(new_form),
        },
    )

    new_form_2 = await client.get("/users/new")
    await client.post(
        "/users",
        data={
            "username": "edit-target",
            "display_name": "Target",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(new_form_2),
        },
    )

    async with db_session_factory() as db:
        target = (
            await db.execute(select(User).where(User.username == "edit-target"))
        ).scalar_one()

    edit_form = await client.get(f"/users/{target.id}/edit")
    response = await client.post(
        f"/users/{target.id}/edit",
        data={
            "username": "taken-name",
            "display_name": "Target",
            "auth_provider": AuthProvider.LOCAL.value,
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(edit_form),
        },
    )
    assert response.status_code == 409
    assert "already exists" in response.text

    async with db_session_factory() as db:
        # Untouched — the rejected edit must not have partially applied.
        unchanged = await db.get(User, target.id)
        assert unchanged.username == "edit-target"


async def test_user_api_update_to_a_duplicate_username_is_rejected(client, db_session_factory):
    from app.auth.api_tokens import create_api_token

    company = await create_company(db_session_factory)

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == "test-superadmin"))
        admin_user = result.scalar_one()
        _token, raw_token = await create_api_token(
            db, admin_user, name="test-token", expires_at=None
        )
    headers = {"Authorization": f"Bearer {raw_token}"}

    create_owner = await client.post(
        "/api/v1/users",
        json={
            "username": "api-owns-the-name",
            "auth_provider": "local",
            "password": "supersecretpw123",
            "memberships": [{"company_id": str(company.id), "access_level": "read"}],
        },
        headers=headers,
    )
    assert create_owner.status_code == 201, create_owner.text

    create_target = await client.post(
        "/api/v1/users",
        json={
            "username": "api-edit-target",
            "auth_provider": "local",
            "password": "supersecretpw123",
            "memberships": [{"company_id": str(company.id), "access_level": "read"}],
        },
        headers=headers,
    )
    assert create_target.status_code == 201, create_target.text
    target_id = create_target.json()["id"]

    response = await client.put(
        f"/api/v1/users/{target_id}",
        json={
            "username": "api-owns-the-name",
            "auth_provider": "local",
            "is_active": True,
            "memberships": [{"company_id": str(company.id), "access_level": "read"}],
        },
        headers=headers,
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]
