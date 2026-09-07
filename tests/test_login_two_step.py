"""Two-step login (username first, then a passkey *or* password) — see
app/web/routes/auth.py's `login_password_form`/`_resolve_webauthn_login_user`
and wiki/Architecture.md's "Login is two steps" note. Mirrors debcontrol's
own test_webauthn.py additions for this feature, adapted to this app's flat
RBAC (no roles) and conftest helpers.
"""

from __future__ import annotations

from typing import Any

from app.auth import webauthn as webauthn_module
from app.db.models.webauthn_credential import WebAuthnCredential
from tests.conftest import create_local_user


class _FakeAuthResult:
    def __init__(self, new_sign_count: int = 1) -> None:
        self.new_sign_count = new_sign_count


async def _add_webauthn_credential(
    db_session_factory: Any, user_id: Any, *, credential_id: bytes = b"cred-1"
) -> WebAuthnCredential:
    async with db_session_factory() as db:
        cred = WebAuthnCredential(
            user_id=user_id,
            name="Test passkey",
            credential_id=credential_id,
            public_key=b"a-fake-public-key",
            sign_count=0,
            device_type="single_device",
            backed_up=False,
        )
        db.add(cred)
        await db.commit()
        await db.refresh(cred)
        return cred


async def test_get_login_has_no_password_field(anonymous_client):
    """Step one is username-only — see auth/login.html; the password field
    (and the passkey option) only appear on step two, /login/password."""
    response = await anonymous_client.get("/login")
    assert response.status_code == 200
    assert 'name="username"' in response.text
    assert 'name="password"' not in response.text


async def test_login_password_screen_offers_passkey_and_password(anonymous_client):
    response = await anonymous_client.get("/login/password", params={"username": "anyone"})
    assert response.status_code == 200
    assert "data-webauthn-login-button" in response.text
    assert 'name="password"' in response.text


async def test_login_password_without_a_username_redirects_to_login(anonymous_client):
    response = await anonymous_client.get("/login/password", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


async def test_login_webauthn_options_gives_the_same_error_for_unknown_username(
    anonymous_client,
):
    """Enumeration-resistance: a nonexistent account and a real one with no
    passkey get an identical response — see
    _resolve_webauthn_login_user's own docstring."""
    response = await anonymous_client.get(
        "/login/webauthn/options", params={"username": "no-such-account"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "No passkeys are registered for this account."


async def test_passwordless_webauthn_login_succeeds_without_a_password(
    anonymous_client, db_session_factory, monkeypatch
):
    """The whole point of the two-step login: a passkey signs an account
    in directly from /login/password, no password ever submitted."""
    user = await create_local_user(
        db_session_factory,
        username="passwordless",
        password="a-very-good-password-123",
        is_superadmin=True,
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"passwordless-cred")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"passwordless-cred",
    )
    monkeypatch.setattr(
        webauthn_module, "verify_authentication", lambda **kwargs: _FakeAuthResult(new_sign_count=3)
    )

    await anonymous_client.get("/login/password", params={"username": "passwordless"})

    options_response = await anonymous_client.get(
        "/login/webauthn/options", params={"username": "passwordless"}
    )
    assert options_response.status_code == 200
    assert "webauthn_challenge" in anonymous_client.cookies
    # No pending_totp cookie at any point — this never went through
    # password/LDAP verification at all.
    assert "totp_pending" not in anonymous_client.cookies

    csrf_token = anonymous_client.cookies.get("csrftoken")
    verify_response = await anonymous_client.post(
        "/login/webauthn/verify",
        data={"credential": "{}", "username": "passwordless", "csrf_token": csrf_token},
    )
    assert verify_response.status_code == 303
    assert verify_response.headers["location"] == "/"
    assert "session" in anonymous_client.cookies


async def test_failed_passwordless_webauthn_login_shows_password_screen_again(
    anonymous_client, db_session_factory, monkeypatch
):
    user = await create_local_user(
        db_session_factory,
        username="passwordless-fail",
        password="a-very-good-password-123",
        is_superadmin=True,
    )
    await _add_webauthn_credential(db_session_factory, user.id, credential_id=b"registered")

    monkeypatch.setattr(
        webauthn_module,
        "credential_id_from_authentication_json",
        lambda credential: b"some-other-credential",
    )

    await anonymous_client.get("/login/password", params={"username": "passwordless-fail"})
    await anonymous_client.get("/login/webauthn/options", params={"username": "passwordless-fail"})
    csrf_token = anonymous_client.cookies.get("csrftoken")

    response = await anonymous_client.post(
        "/login/webauthn/verify",
        data={"credential": "{}", "username": "passwordless-fail", "csrf_token": csrf_token},
    )
    assert response.status_code == 401
    assert "data-webauthn-login-button" in response.text
