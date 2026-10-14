"""Each account's own Dashboard (`app.services.dashboard_layout`): order
and hidden sections, on the page and in the REST API. Ported from
debcontrol."""

from __future__ import annotations

import re
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.user import User
from app.services import dashboard_layout


def test_a_stored_layout_survives_added_and_removed_sections() -> None:
    layout = dashboard_layout.resolve(
        {"order": ["recent", "gone", "overview", "recent"], "hidden": ["trend", "gone"]}
    )

    # Known keys in the stored order, then every section it did not mention.
    assert layout.order == ("recent", "overview", "companies", "trend", "types")
    assert layout.hidden == frozenset({"trend"})
    assert "trend" not in layout.visible and layout.visible[0] == "recent"
    assert dashboard_layout.resolve(None) == dashboard_layout.DEFAULT
    assert dashboard_layout.resolve("nonsense") == dashboard_layout.DEFAULT


def test_moving_and_hiding() -> None:
    layout = dashboard_layout.DEFAULT

    moved = dashboard_layout.move(layout, "recent", up=True)
    at_top = dashboard_layout.move(layout, "overview", up=True)
    hidden = dashboard_layout.set_hidden(moved, "companies", hidden=True)

    assert moved.order[-2:] == ("recent", "types")
    assert at_top == layout
    assert hidden.hidden == frozenset({"companies"})
    assert dashboard_layout.to_store(layout) is None
    assert dashboard_layout.to_store(hidden) == {
        "order": list(moved.order),
        "hidden": ["companies"],
    }


async def test_arranging_the_dashboard(client: AsyncClient, db_session_factory: Any) -> None:
    page = await client.get("/dashboard")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    csrf = match.group(1)

    def sections(text: str) -> str:
        """The page below the "Arrange this page" box."""
        after = text[text.index('class="dashboard-arrange"') :]
        return after[after.index("</details>") :]

    body = sections(page.text)
    assert body.index("stat-card") < body.index("Recent events")
    for action, section in (
        ("up", "recent"),
        ("up", "recent"),
        ("up", "recent"),
        ("up", "recent"),
        ("hide", "overview"),
    ):
        response = await client.post(
            "/dashboard/layout",
            data={"csrf_token": csrf, "action": action, "section": section},
            follow_redirects=False,
        )
        assert response.headers["location"] == "/dashboard?arrange=1"
    arranged = await client.get("/dashboard?arrange=1")
    panel = await client.get("/dashboard/panel")
    unknown = await client.post(
        "/dashboard/layout", data={"csrf_token": csrf, "action": "up", "section": "nope"}
    )

    body = sections(arranged.text)
    assert "Recent events" in body
    # The counts are gone from the page — also from the live-refreshed
    # panel — but still listed to bring back.
    assert "stat-card" not in body and "stat-card" not in panel.text
    assert '<details class="dashboard-arrange" open>' in arranged.text
    assert 'value="show"' in arranged.text and 'value="reset"' in arranged.text
    assert unknown.status_code == 400
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None and user.dashboard_layout is not None
        assert user.dashboard_layout["order"][0] == "recent"

    await client.post("/dashboard/layout", data={"csrf_token": csrf, "action": "reset"})
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None and user.dashboard_layout is None


async def test_dashboard_layout_api(
    client: AsyncClient, login_as: Any, db_session_factory: Any
) -> None:
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw}"}
    url = "/api/v1/account/dashboard-layout"

    default = (await client.get(url, headers=headers)).json()
    saved = await client.put(
        url, headers=headers, json={"order": ["recent", "overview"], "hidden": ["trend"]}
    )
    bad = await client.put(url, headers=headers, json={"order": ["nope"]})
    reset = await client.put(url, headers=headers, json={})

    assert default["order"] == default["sections"] and default["hidden"] == []
    assert saved.status_code == 200
    assert saved.json()["order"][:2] == ["recent", "overview"]
    assert saved.json()["hidden"] == ["trend"]
    assert bad.status_code == 422
    assert reset.json()["order"] == reset.json()["sections"]
