"""Company scoping (`app.auth.scope`) and the superadmin-only pages —
the HoneyHive equivalent of debcontrol's test_rbac.py/test_access_scope.py,
adapted to the flat superadmin/company+access_level model (see
`app.db.models.user`'s module docstring)."""

from __future__ import annotations

import uuid

import pytest

from app.auth.scope import (
    ensure_company_access,
    has_company_access,
    visible_company_id,
)
from app.db.models.user import AccessLevel, AuthProvider, User
from tests.conftest import create_company

# asyncio_mode = "auto" (pyproject.toml) already runs every `async def
# test_*` under pytest-asyncio — no explicit `pytestmark` needed, and
# adding one would incorrectly apply to the plain sync tests below too.


def _user(*, is_superadmin=False, company_id=None, access_level=None) -> User:
    return User(
        username="x",
        auth_provider=AuthProvider.LOCAL,
        is_superadmin=is_superadmin,
        company_id=company_id,
        access_level=access_level,
    )


def test_superadmin_has_access_to_any_company():
    admin = _user(is_superadmin=True)
    assert has_company_access(admin, uuid.uuid4(), write=True)
    assert visible_company_id(admin) is None


def test_read_user_can_read_but_not_write_own_company():
    company_id = uuid.uuid4()
    user = _user(company_id=company_id, access_level=AccessLevel.READ)
    assert has_company_access(user, company_id, write=False)
    assert not has_company_access(user, company_id, write=True)


def test_read_write_user_can_write_own_company():
    company_id = uuid.uuid4()
    user = _user(company_id=company_id, access_level=AccessLevel.READ_WRITE)
    assert has_company_access(user, company_id, write=True)


def test_user_has_no_access_to_a_different_company():
    own = uuid.uuid4()
    other = uuid.uuid4()
    user = _user(company_id=own, access_level=AccessLevel.READ_WRITE)
    assert not has_company_access(user, other, write=False)
    assert not has_company_access(user, other, write=True)


def test_visible_company_id_is_the_users_own_company():
    company_id = uuid.uuid4()
    user = _user(company_id=company_id, access_level=AccessLevel.READ)
    assert visible_company_id(user) == company_id


def test_ensure_company_access_raises_404_not_403():
    user = _user(company_id=uuid.uuid4(), access_level=AccessLevel.READ)
    with pytest.raises(Exception) as exc_info:
        ensure_company_access(user, uuid.uuid4())
    assert getattr(exc_info.value, "status_code", None) == 404


async def test_companies_page_is_superadmin_only(client, db_session_factory, login_as):
    company = await create_company(db_session_factory)
    response = await client.get("/companies")
    assert response.status_code == 200  # client fixture is a superadmin

    await login_as(
        client, is_superadmin=False, company_id=company.id, access_level=AccessLevel.READ_WRITE
    )
    response = await client.get("/companies")
    assert response.status_code == 403


async def test_users_page_is_superadmin_only(client, db_session_factory, login_as):
    company = await create_company(db_session_factory)
    await login_as(
        client, is_superadmin=False, company_id=company.id, access_level=AccessLevel.READ_WRITE
    )
    response = await client.get("/users")
    assert response.status_code == 403


async def test_audit_page_is_superadmin_only(client, db_session_factory, login_as):
    company = await create_company(db_session_factory)
    await login_as(
        client, is_superadmin=False, company_id=company.id, access_level=AccessLevel.READ_WRITE
    )
    response = await client.get("/audit")
    assert response.status_code == 403


async def test_read_only_user_cannot_reach_honeypot_write_routes(
    client, db_session_factory, login_as
):
    company = await create_company(db_session_factory)
    await login_as(client, is_superadmin=False, company_id=company.id, access_level=AccessLevel.READ)
    response = await client.get("/honeypots/new")
    # get is unguarded (read access is enough to see the form render);
    # the actual POST is what require_write gates.
    assert response.status_code in (200, 403)
    response = await client.post("/honeypots", data={})
    assert response.status_code == 403
