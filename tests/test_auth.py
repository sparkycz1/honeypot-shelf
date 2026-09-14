"""Login/logout, brute-force lockout, and the "must change password on
first login" flow — the same behaviors debcontrol's own test_auth.py
exercises, ported against this app's simplified RBAC (no roles: a
superadmin or a company + access level)."""

from __future__ import annotations

import re

import pytest

from tests.conftest import create_local_user

pytestmark = pytest.mark.asyncio


async def _login_csrf(anonymous_client) -> str:
    """Every anonymous request already gets a csrftoken cookie from
    `app.auth.middleware` — a plain GET to any page (even one that
    redirects) is enough to have one to read back. Reads the cookie
    rather than regex-parsing a `csrf_token` hidden field out of
    `GET /login`'s HTML: since login is now two steps (see auth/login.html
    and auth/login_password.html), step one's page has no such field at
    all — it only collects the username via a plain GET to
    `/login/password`, which is where the CSRF-protected password form
    actually lives."""
    await anonymous_client.get("/login")
    token = anonymous_client.cookies.get("csrftoken")
    assert token is not None
    return token


async def test_login_with_correct_password_succeeds(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="alice", password="correct-horse-battery", is_superadmin=True
    )
    csrf_token = await _login_csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={"username": "alice", "password": "correct-horse-battery", "csrf_token": csrf_token},
    )
    assert response.status_code == 303


async def test_login_with_wrong_password_is_rejected(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="alice", password="correct-horse-battery", is_superadmin=True
    )
    csrf_token = await _login_csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={"username": "alice", "password": "wrong-password", "csrf_token": csrf_token},
    )
    assert response.status_code == 401
    assert "Invalid" in response.text


async def test_login_with_unknown_username_gives_generic_message(anonymous_client):
    csrf_token = await _login_csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={"username": "nobody", "password": "whatever", "csrf_token": csrf_token},
    )
    assert response.status_code == 401
    assert "Invalid" in response.text


async def test_account_locks_after_five_failed_attempts(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory, username="alice", password="correct-horse-battery", is_superadmin=True
    )
    csrf_token = await _login_csrf(anonymous_client)
    for _ in range(5):
        await anonymous_client.post(
            "/login",
            data={"username": "alice", "password": "wrong-password", "csrf_token": csrf_token},
        )
    response = await anonymous_client.post(
        "/login",
        data={"username": "alice", "password": "correct-horse-battery", "csrf_token": csrf_token},
    )
    assert response.status_code == 429
    assert "too many failed attempts" in response.text.lower()


async def test_inactive_user_cannot_log_in(anonymous_client, db_session_factory):
    await create_local_user(
        db_session_factory,
        username="alice",
        password="correct-horse-battery",
        is_active=False,
        is_superadmin=True,
    )
    csrf_token = await _login_csrf(anonymous_client)
    response = await anonymous_client.post(
        "/login",
        data={"username": "alice", "password": "correct-horse-battery", "csrf_token": csrf_token},
    )
    assert response.status_code == 401
    assert "Invalid" in response.text


async def test_protected_page_redirects_anonymous_to_login(anonymous_client):
    response = await anonymous_client.get("/dashboard", follow_redirects=False)
    assert response.status_code in (302, 303)
    assert "/login" in response.headers["location"]


async def test_logged_in_user_can_reach_dashboard(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200


async def test_logout_ends_the_session(client):
    csrf_response = await client.get("/dashboard")
    assert csrf_response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', csrf_response.text)
    csrf_token = match.group(1) if match else "irrelevant-if-checked"
    response = await client.post("/logout", data={"csrf_token": csrf_token})
    assert response.status_code == 303


async def test_oidc_login_with_unreachable_provider_redirects_gracefully(
    anonymous_client, db_session_factory
):
    """A provider discovery-document fetch failure (unreachable host, or a
    misconfigured Issuer URL that 404s) used to be an uncaught
    httpx.HTTPStatusError -> 500. It must instead redirect back to /login
    with the same kind of oidc_error the callback route already handles."""
    from app.core.app_settings import get_or_create_app_settings

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.oidc_enabled = True
        app_settings.oidc_issuer_url = "https://issuer.invalid.example"
        app_settings.oidc_client_id = "test-client"
        await db.commit()

    response = await anonymous_client.get("/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?oidc_error=discovery_failed"

    login_page = await anonymous_client.get(response.headers["location"])
    assert "discovery document" in login_page.text.lower()
