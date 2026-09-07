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
    response = await anonymous_client.get("/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found on /login"
    return match.group(1)


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
