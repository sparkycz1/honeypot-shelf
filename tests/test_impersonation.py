"""Impersonation ("sign in as another account") — superadmin-only. Ported
from an identical debcontrol test suite, adapted for this app's own RBAC
(no roles/permissions — see `app/db/models/user.py`'s module docstring),
so the guardrail against impersonating another admin-equivalent account
becomes "can't impersonate another superadmin" instead of debcontrol's
"can't impersonate an account holding user.impersonate"."""

from __future__ import annotations

import re
from typing import Any

from app.auth.sessions import IMPERSONATION_RETURN_COOKIE_NAME, SESSION_COOKIE_NAME
from tests.conftest import ADMIN_USERNAME, _create_user


async def _csrf(client: Any) -> str:
    await client.get("/dashboard")
    token = client.cookies.get("csrftoken")
    assert token is not None
    return token


async def test_superadmin_can_impersonate_and_stop_returns_to_own_account(
    client, db_session_factory
):
    target, _target_token = await _create_user(db_session_factory, username="target-user")

    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert client.cookies.get(IMPERSONATION_RETURN_COOKIE_NAME) is not None

    # Now acting as the target — the topbar shows their name.
    account_page = await client.get("/account")
    assert account_page.status_code == 200
    assert "target-user" in account_page.text

    # "Logging out" while impersonating returns to the superadmin, not the
    # login page.
    logout_csrf = client.cookies.get("csrftoken")
    stop = await client.post("/logout", data={"csrf_token": logout_csrf})
    assert stop.status_code == 303
    assert stop.headers["location"] == "/users"
    assert client.cookies.get(IMPERSONATION_RETURN_COOKIE_NAME) is None

    whoami = await client.get("/account")
    assert whoami.status_code == 200
    assert ADMIN_USERNAME in whoami.text


async def test_impersonation_requires_superadmin(client, login_as):
    target = await login_as(client, username="not-an-admin")
    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 403


async def test_cannot_impersonate_self(client):
    users_page = await client.get("/users")
    row = next(r for r in users_page.text.split("<tr>") if f">{ADMIN_USERNAME}<" in r)
    match = re.search(r"/users/([0-9a-f-]{36})/edit", row)
    assert match is not None, row
    self_id = match.group(1)

    csrf_token = await _csrf(client)
    response = await client.post(f"/users/{self_id}/impersonate", data={"csrf_token": csrf_token})
    assert response.status_code == 400


async def test_cannot_impersonate_another_superadmin(client, db_session_factory):
    other_admin, _ = await _create_user(
        db_session_factory, username="other-admin", is_superadmin=True
    )
    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{other_admin.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 400
    assert "impersonate others" in response.text


async def test_cannot_impersonate_disabled_account(client, db_session_factory):
    target, _ = await _create_user(db_session_factory, username="disabled-target")
    async with db_session_factory() as db:
        db_target = await db.get(type(target), target.id)
        assert db_target is not None
        db_target.is_active = False
        await db.commit()

    csrf_token = await _csrf(client)
    response = await client.post(
        f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 400


# Note: "can't stack a second impersonation" (409) is defense-in-depth that
# isn't independently reachable through this route in this app's own RBAC
# model — the impersonated session is never a superadmin (impersonating one
# is already rejected above), and this whole router requires superadmin, so
# an impersonated session can never reach it to try stacking. Same as
# debcontrol, which has no test for this either for the identical reason.


async def test_impersonation_is_audit_logged(client, db_session_factory):
    target, _ = await _create_user(db_session_factory, username="audited-target")
    csrf_token = await _csrf(client)
    await client.post(f"/users/{target.id}/impersonate", data={"csrf_token": csrf_token})
    logout_csrf = client.cookies.get("csrftoken")
    await client.post("/logout", data={"csrf_token": logout_csrf})

    # Log back in as a fresh superadmin to read the audit log.
    _admin2, admin2_token = await _create_user(
        db_session_factory, username="audit-reader", is_superadmin=True
    )
    client.cookies.set(SESSION_COOKIE_NAME, admin2_token)
    audit_page = await client.get("/audit")
    assert "user.impersonate.start" in audit_page.text
    assert "user.impersonate.stop" in audit_page.text


async def test_users_list_has_no_nested_forms(client, db_session_factory):
    """Regression guard for a real bug: the per-row "Sign in as" <form>
    used to sit nested inside the page's own bulk-actions <form> — invalid
    HTML that a browser silently mangles (see users/list.html's own
    comment) — which made the button submit to POST /users (create-user,
    422) instead of POST /users/{id}/impersonate. A lightweight
    depth-counting scan, not a full HTML parser: any '<form' encountered
    before the matching '</form>' of an already-open one means nesting."""
    await _create_user(db_session_factory, username="nested-form-check")
    response = await client.get("/users")
    assert response.status_code == 200

    depth = 0
    for token in re.findall(r"</?form\b", response.text):
        if token == "<form":
            assert depth == 0, "found a <form> nested inside another <form> on /users"
            depth += 1
        else:
            assert depth == 1, "found a </form> with no matching open <form> on /users"
            depth -= 1
    assert depth == 0


async def test_users_list_impersonate_form_targets_the_impersonate_route(
    client, db_session_factory
):
    target, _ = await _create_user(db_session_factory, username="form-action-check")
    response = await client.get("/users")
    assert response.status_code == 200
    match = re.search(
        rf'<form method="post" action="([^"]*)" class="inline-form"[^>]*'
        rf'confirm=[^>]*{target.username}',
        response.text,
    )
    assert match is not None, "couldn't find the target's own impersonate <form>"
    assert match.group(1) == f"/users/{target.id}/impersonate"
