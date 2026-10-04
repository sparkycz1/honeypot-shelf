"""Limits on a single API token: read-only, and companies — on top of
whatever the owning account may do (`ApiToken.read_only`,
`ApiToken.company_ids`)."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.api_token import ApiToken
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from tests.conftest import create_company


async def _fleet(db_session_factory: Any) -> tuple[Any, Any, Any]:
    """Two companies with one honeypot each; returns the company ids and
    the first honeypot's id."""
    atlas = await create_company(db_session_factory, name="Atlas")
    borealis = await create_company(db_session_factory, name="Borealis")
    async with db_session_factory() as db:
        first = Honeypot(companies=[await db.get(Company, atlas.id)], name="atlas-honey")
        db.add_all(
            [first, Honeypot(companies=[await db.get(Company, borealis.id)], name="borealis-honey")]
        )
        await db.commit()
        return atlas.id, borealis.id, first.id


async def _token(db_session_factory: Any, user_id: Any, **limits: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        _token, raw = await create_api_token(db, user, name="t", expires_at=None, **limits)
    return {"Authorization": f"Bearer {raw}"}


async def _names(client: Any, headers: dict[str, str]) -> set[str]:
    response = await client.get("/api/v1/honeypots", headers=headers)
    assert response.status_code == 200
    body = response.json()
    return {h["name"] for h in (body["honeypots"] if isinstance(body, dict) else body)}


async def test_read_only_token_reads_but_never_writes(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    _atlas, _borealis, honeypot_id = await _fleet(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    headers = await _token(db_session_factory, user.id, read_only=True)

    assert await _names(client, headers) == {"atlas-honey", "borealis-honey"}
    refused = await client.post(
        f"/api/v1/honeypots/{honeypot_id}/acknowledge", json={"hours": 1}, headers=headers
    )
    assert refused.status_code == 403
    assert refused.json()["detail"] == "This API token is read-only."
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None and honeypot.acknowledged_at is None


async def test_company_limited_superadmin_token_stays_inside_its_companies(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, borealis_id, honeypot_id = await _fleet(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    headers = await _token(db_session_factory, user.id, company_ids=[atlas_id])

    assert await _names(client, headers) == {"atlas-honey"}
    # It can still manage what is inside the limit...
    inside = await client.post(
        f"/api/v1/honeypots/{honeypot_id}/acknowledge", json={"hours": 1}, headers=headers
    )
    assert inside.status_code == 200
    # ...but nothing that reaches across companies.
    assert (await client.get("/api/v1/users", headers=headers)).status_code == 403
    found = await client.get("/api/v1/search", params={"q": "honey"}, headers=headers)
    labels = [hit["label"] for group in found.json()["results"] for hit in group["hits"]]
    assert labels == ["atlas-honey"]

    # The same account with an unlimited token still sees everything.
    unlimited = await _token(db_session_factory, user.id)
    assert await _names(client, unlimited) == {"atlas-honey", "borealis-honey"}
    assert (await client.get("/api/v1/users", headers=unlimited)).status_code == 200
    assert borealis_id != atlas_id


async def test_company_limit_narrows_a_member_account_too(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, borealis_id, _honeypot = await _fleet(db_session_factory)
    user = await login_as(
        client,
        username="member",
        company_id=atlas_id,
        access_level=AccessLevel.READ_WRITE,
        api_access_enabled=True,
    )
    # Limited to a company the account is not a member of: sees nothing.
    headers = await _token(db_session_factory, user.id, company_ids=[borealis_id])
    assert await _names(client, headers) == set()
    assert await _names(client, await _token(db_session_factory, user.id)) == {"atlas-honey"}


async def test_limited_tokens_cannot_register_a_honeypot(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, _borealis, _honeypot = await _fleet(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    for limits in ({"read_only": True}, {"company_ids": [atlas_id]}):
        headers = await _token(db_session_factory, user.id, **limits)
        response = await client.post("/api/inform", json={"hostname": "new"}, headers=headers)
        assert response.status_code in (401, 403)


async def test_account_page_creates_a_limited_token(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, _borealis, _honeypot = await _fleet(db_session_factory)
    await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)

    page = await client.get("/account")
    assert 'name="read_only"' in page.text and 'name="company_ids"' in page.text
    created = await client.post(
        "/account/api-tokens",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "name": "grafana",
            "read_only": "on",
            "company_ids": [str(atlas_id)],
        },
    )
    assert created.status_code == 200
    raw = re.search(r"hhpat_[A-Za-z0-9_-]+", created.text)
    assert raw is not None
    assert "read-only" in created.text

    async with db_session_factory() as db:
        token = (await db.execute(select(ApiToken))).scalar_one()
        assert token.read_only is True
        assert token.company_ids == [str(atlas_id)]

    headers = {"Authorization": f"Bearer {raw.group(0)}"}
    assert await _names(client, headers) == {"atlas-honey"}
