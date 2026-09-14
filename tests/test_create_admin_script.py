"""`scripts/create_admin.py` — bootstraps the very first superadmin
account. Regression guard: this script predates the multi-company
`CompanyMembership` migration and, until fixed here, still passed the
old `company_id`/`access_level` kwargs straight to `User(...)` — kwargs
that model hasn't accepted directly in a long time (see
`app.db.models.company_membership`) — so running it on any fresh install
crashed with `TypeError: 'company_id' is an invalid keyword argument for
User`. Never caught before because nothing exercised this script: it's
normally run exactly once, by hand, by whoever bootstraps a deployment,
not from a web request or an existing test."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.user import AuthProvider, User

pytestmark = pytest.mark.asyncio


async def test_create_admin_creates_a_superadmin_with_no_memberships(
    db_session_factory, monkeypatch
):
    from scripts import create_admin

    monkeypatch.setattr(create_admin, "AsyncSessionLocal", db_session_factory)

    await create_admin._create_admin("freshadmin", "a-perfectly-fine-password")

    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == "freshadmin"))
        user = result.scalar_one()
        assert user.is_superadmin is True
        assert user.auth_provider == AuthProvider.LOCAL
        assert user.must_change_password is True
        assert user.memberships == []


async def test_create_admin_refuses_a_duplicate_username(db_session_factory, monkeypatch):
    from scripts import create_admin

    monkeypatch.setattr(create_admin, "AsyncSessionLocal", db_session_factory)

    await create_admin._create_admin("dupe-admin", "a-perfectly-fine-password")
    with pytest.raises(SystemExit):
        await create_admin._create_admin("dupe-admin", "another-fine-password")
