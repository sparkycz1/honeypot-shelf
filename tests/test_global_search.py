"""The header search box (`app.services.global_search`): what it finds,
and that it shows an account only what that account could open anyway."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from tests.conftest import create_company


async def _seed(db_session_factory: Any) -> tuple[Any, Any]:
    """Two companies, one honeypot each; returns their ids."""
    atlas = await create_company(db_session_factory, name="Atlas Corp")
    other = await create_company(db_session_factory, name="Borealis")
    async with db_session_factory() as db:
        db.add_all(
            [
                Honeypot(
                    companies=[await db.get(Company, atlas.id)],
                    name="atlas-honey1",
                    ip_address="10.0.0.1",
                ),
                Honeypot(
                    companies=[await db.get(Company, other.id)],
                    name="borealis-atlas-decoy",
                    ip_address="10.0.0.2",
                ),
            ]
        )
        await db.commit()
    return atlas.id, other.id


async def test_search_page_groups_matches_by_kind(client: Any, db_session_factory: Any) -> None:
    await _seed(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        honeypot = (await db.execute(select(Honeypot))).scalars().first()
        db.add(
            NotificationRule(
                user_id=user.id,
                name="Atlas alerts",
                scope=NotificationScope.HONEYPOT,
                honeypots=[honeypot],
                delivery_channel=NotificationChannel.WEBHOOK,
                webhook_url="https://hooks.example.com/abc",
            )
        )
        await db.commit()

    page = await client.get("/search", params={"q": "atlas"})
    assert page.status_code == 200
    for expected in ("atlas-honey1", "borealis-atlas-decoy", "Atlas Corp", "Atlas alerts"):
        assert expected in page.text
    assert "Borealis</a>" not in page.text

    assert "atlas-honey1" in (await client.get("/search", params={"q": "10.0.0.1"})).text
    assert (await client.get("/search")).status_code == 200
    short = await client.get("/search", params={"q": "a"})
    assert "atlas-honey1" not in short.text
    nothing = await client.get("/search", params={"q": "zzz-nope"})
    assert "atlas-honey1" not in nothing.text and "zzz-nope" in nothing.text


async def test_every_page_has_the_search_box(client: Any) -> None:
    page = await client.get("/dashboard")
    assert 'action="/search"' in page.text and "data-global-search" in page.text


async def test_search_stays_inside_the_accounts_companies(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, _other_id = await _seed(db_session_factory)
    await login_as(client, username="reader", company_id=atlas_id, access_level=AccessLevel.READ)

    page = await client.get("/search", params={"q": "atlas"})
    assert "atlas-honey1" in page.text and "Atlas Corp" in page.text
    assert "borealis-atlas-decoy" not in page.text

    # Users are a superadmin-only kind.
    assert "/users/" not in (await client.get("/search", params={"q": "reader"})).text


async def test_api_search(client: Any, login_as: Any, db_session_factory: Any) -> None:
    await _seed(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw_token}"}

    found = await client.get("/api/v1/search", params={"q": "atlas"}, headers=headers)
    assert found.status_code == 200
    kinds = {group["kind"]: group["hits"] for group in found.json()["results"]}
    assert set(kinds) == {"honeypots", "companies"}
    assert kinds["honeypots"][0]["href"].startswith("/honeypots/")

    short = await client.get("/api/v1/search", params={"q": "a"}, headers=headers)
    assert short.status_code == 422
