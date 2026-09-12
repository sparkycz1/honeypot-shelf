"""An admin can set/override a user's `email` from the Users edit form —
"uživatel si nastaví email u sebe v profilu - může nastavit i admin" — the
default destination for that user's Notifications."""

from __future__ import annotations

import re

import pytest

from app.db.models.user import AuthProvider, User
from tests.conftest import ADMIN_USERNAME, create_company

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_admin_sets_email_on_create(client, db_session_factory):
    company = await create_company(db_session_factory)
    form = await client.get("/users/new")
    response = await client.post(
        "/users",
        data={
            "username": "new-user-with-email",
            "display_name": "New User",
            "email": "new-user@example.com",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(User).where(User.username == "new-user-with-email"))
        user = result.scalar_one()
        assert user.email == "new-user@example.com"


async def test_admin_edits_existing_users_email(client, db_session_factory):
    company = await create_company(db_session_factory)
    new_form = await client.get("/users/new")
    await client.post(
        "/users",
        data={
            "username": "edit-target",
            "display_name": "Edit Target",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(new_form),
        },
    )
    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(User).where(User.username == "edit-target"))
        user_id = result.scalar_one().id

    edit_form = await client.get(f"/users/{user_id}/edit")
    response = await client.post(
        f"/users/{user_id}/edit",
        data={
            "username": "edit-target",
            "display_name": "Edit Target",
            "email": "admin-set@example.com",
            "auth_provider": AuthProvider.LOCAL.value,
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(edit_form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(User, user_id)
        assert refreshed is not None
        assert refreshed.email == "admin-set@example.com"


async def test_editing_a_user_without_changing_their_membership_does_not_crash(
    client, db_session_factory
):
    """Regression guard: `_apply_memberships` used to delete then
    immediately re-insert a user's memberships in the same flush — when
    the submitted (company_id, access_level) pair was unchanged, the
    insert could reach the database before the delete did, tripping
    `uq_company_membership_user_company` with a raw `IntegrityError`
    instead of being the no-op it should be. Found via the email field
    added in this same change; unrelated to it."""
    company = await create_company(db_session_factory)
    new_form = await client.get("/users/new")
    await client.post(
        "/users",
        data={
            "username": "unchanged-membership",
            "display_name": "Unchanged",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(new_form),
        },
    )
    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(User).where(User.username == "unchanged-membership"))
        user_id = result.scalar_one().id

    edit_form = await client.get(f"/users/{user_id}/edit")
    response = await client.post(
        f"/users/{user_id}/edit",
        data={
            "username": "unchanged-membership",
            "display_name": "Unchanged Still",
            "auth_provider": AuthProvider.LOCAL.value,
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(edit_form),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


async def test_api_editing_a_user_without_changing_their_membership_does_not_crash(
    client, db_session_factory
):
    """API-side equivalent of the regression guard above —
    `api_v1_users.update_user_api` had the identical bug."""
    from app.auth.api_tokens import create_api_token

    company = await create_company(db_session_factory)
    new_form = await client.get("/users/new")
    await client.post(
        "/users",
        data={
            "username": "api-unchanged-membership",
            "display_name": "Unchanged",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(new_form),
        },
    )
    async with db_session_factory() as db:
        from sqlalchemy import select

        target = (
            await db.execute(select(User).where(User.username == "api-unchanged-membership"))
        ).scalar_one()
        target_id = target.id
        admin = (
            await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()
        _token, raw_token = await create_api_token(db, admin, name="test-token", expires_at=None)

    response = await client.put(
        f"/api/v1/users/{target_id}",

        headers={"Authorization": f"Bearer {raw_token}"},
        json={
            "username": "api-unchanged-membership",
            "display_name": "Unchanged Still",
            "auth_provider": AuthProvider.LOCAL.value,
            "is_superadmin": False,
            "memberships": [{"company_id": str(company.id), "access_level": "read"}],
            "api_access_enabled": False,
            "is_active": True,
        },
    )
    assert response.status_code == 200


async def test_invalid_email_is_rejected(client, db_session_factory):
    company = await create_company(db_session_factory)
    form = await client.get("/users/new")
    response = await client.post(
        "/users",
        data={
            "username": "bad-email-user",
            "display_name": "Bad Email",
            "email": "not-an-email",
            "auth_provider": AuthProvider.LOCAL.value,
            "password": "supersecretpw123",
            f"membership__{company.id}": "read",
            "csrf_token": _csrf_from(form),
        },
    )
    assert response.status_code == 422
