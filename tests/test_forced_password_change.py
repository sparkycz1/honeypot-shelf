"""An account whose password an administrator set (a new account, or a
reset) can sign in with it and do exactly one thing: replace it."""

from __future__ import annotations

from typing import Any

import pytest

from app.auth.security import hash_password, verify_password
from app.db.models.access_level import AccessLevel
from app.db.models.user import User
from tests.conftest import create_company

_FROM_ADMIN = "from-the-administrator-1"
_OWN = "something-only-i-know-2"


async def _sign_in_with_admin_set_password(
    client: Any, login_as: Any, db_session_factory: Any
) -> User:
    company = await create_company(db_session_factory)
    user: User = await login_as(
        client,
        company_id=company.id,
        access_level=AccessLevel.READ_WRITE,
        password_hash=hash_password(_FROM_ADMIN),
        must_change_password=True,
    )
    return user


def _csrf(page_text: str) -> str:
    return page_text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]


@pytest.mark.asyncio
async def test_every_page_leads_to_the_password_change(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _sign_in_with_admin_set_password(client, login_as, db_session_factory)

    for path in ("/dashboard", "/honeypots", "/account", "/events", "/account/notifications"):
        response = await client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"] == "/account/password", path

    as_json = await client.get("/honeypots", headers={"accept": "application/json"})
    assert as_json.status_code == 403

    page = await client.get("/account/password")
    assert page.status_code == 200
    assert "Choose your own password" in page.text
    # No navigation to click through — only the form and a way out.
    assert 'href="/honeypots"' not in page.text
    assert 'action="/logout"' in page.text


@pytest.mark.asyncio
async def test_changing_the_password_opens_the_app(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    user = await _sign_in_with_admin_set_password(client, login_as, db_session_factory)
    csrf = _csrf((await client.get("/account/password")).text)

    def attempt(new: str, confirm: str | None = None, current: str = _FROM_ADMIN) -> Any:
        return client.post(
            "/account/password",
            data={
                "csrf_token": csrf,
                "current_password": current,
                "new_password": new,
                "confirm_password": new if confirm is None else confirm,
            },
        )

    # Keeping the password the administrator knows is not a change.
    same = await attempt(_FROM_ADMIN)
    assert same.status_code == 422
    assert "must differ from the current one" in same.text
    assert "Choose your own password" in same.text
    assert (await client.get("/dashboard")).status_code == 303

    changed = await attempt(_OWN)
    assert changed.status_code == 303 and changed.headers["location"] == "/"

    async with db_session_factory() as db:
        stored = await db.get(User, user.id)
        assert stored is not None
        assert stored.must_change_password is False
        assert stored.password_hash is not None and verify_password(stored.password_hash, _OWN)

    assert (await client.get("/honeypots")).status_code == 200
    # Nothing left to force: the page hands over to the ordinary one.
    again = await client.get("/account/password")
    assert again.status_code == 303 and again.headers["location"] == "/account"


@pytest.mark.asyncio
async def test_logging_out_stays_possible(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _sign_in_with_admin_set_password(client, login_as, db_session_factory)
    csrf = _csrf((await client.get("/account/password")).text)
    out = await client.post("/logout", data={"csrf_token": csrf})
    assert out.status_code == 303
    assert out.headers["location"] != "/account/password"


@pytest.mark.asyncio
async def test_an_ordinary_account_is_not_sent_anywhere(client: Any) -> None:
    assert (await client.get("/honeypots")).status_code == 200
    page = await client.get("/account")
    assert page.status_code == 200
    assert "set by an administrator" not in page.text
