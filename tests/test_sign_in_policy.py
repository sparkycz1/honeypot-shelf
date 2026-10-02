"""Settings -> Security's sign-in policy (`app.auth.session_policy`):
session lifetime, failed-attempt lockout and the network allowlist."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.auth import session_policy
from app.auth.api_tokens import create_api_token
from app.auth.login import check_password
from app.auth.sessions import create_session
from app.core.app_settings import get_or_create_app_settings
from app.db.models.user import User
from tests.conftest import create_local_user


async def _set_settings(
    db_session_factory: async_sessionmaker[AsyncSession], **values: object
) -> None:
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        for key, value in values.items():
            setattr(app_settings, key, value)
        await db.commit()
    session_policy.invalidate()


def _policy_form(client, **overrides: str) -> dict[str, str]:
    form = {
        "csrf_token": client.cookies.get("csrftoken"),
        "session_idle_timeout_minutes": "720",
        "session_absolute_max_hours": "720",
        "login_max_failed_attempts": "5",
        "login_lockout_minutes": "15",
        "login_allowed_networks": "",
    }
    form.update(overrides)
    return form


def test_parse_networks_and_ip_allowed():
    networks, invalid = session_policy.parse_networks("192.168.1.10/24, 10.0.0.5\nnonsense")

    assert [str(n) for n in networks] == ["192.168.1.0/24", "10.0.0.5/32"]
    assert invalid == ["nonsense"]
    assert session_policy.ip_allowed("192.168.1.77", networks)
    assert session_policy.ip_allowed("::ffff:10.0.0.5", networks)
    assert not session_policy.ip_allowed("172.16.0.1", networks)
    assert not session_policy.ip_allowed(None, networks)
    assert session_policy.ip_allowed("172.16.0.1", ())


async def test_defaults_match_the_old_hardcoded_values(db_session_factory):
    async with db_session_factory() as db:
        policy = await session_policy.load_policy(db)
    assert policy.idle_timeout == timedelta(hours=12)
    assert policy.absolute_max == timedelta(days=30)
    assert policy.max_failed_attempts == 5
    assert policy.lockout_duration == timedelta(minutes=15)
    assert policy.allowed_networks == ()


async def test_session_lifetime_comes_from_settings(db_session_factory):
    await _set_settings(db_session_factory, session_idle_timeout_minutes=30)
    user = await create_local_user(db_session_factory, username="lifetime", password="pw-12345678")
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        session, _token = await create_session(db, db_user, ip_address=None, user_agent=None)

    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    remaining = expires_at - datetime.now(UTC)
    assert timedelta(minutes=25) < remaining <= timedelta(minutes=30)


async def test_saving_the_sign_in_policy(client, db_session_factory):
    await client.get("/settings?tab=security")
    response = await client.post(
        "/settings/sign-in-policy",
        data=_policy_form(
            client,
            session_idle_timeout_minutes="60",
            login_max_failed_attempts="3",
            login_allowed_networks="127.0.0.0/8\n10.0.0.0/8",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 303
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.session_idle_timeout_minutes == 60
        assert app_settings.login_max_failed_attempts == 3
        assert app_settings.login_allowed_networks == "127.0.0.0/8\n10.0.0.0/8"


async def test_out_of_range_numbers_are_refused(client, db_session_factory):
    await client.get("/settings?tab=security")
    response = await client.post(
        "/settings/sign-in-policy",
        data=_policy_form(client, session_idle_timeout_minutes="1"),
    )

    assert response.status_code == 200
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).session_idle_timeout_minutes == 720


async def test_sign_in_policy_refuses_networks_that_exclude_the_saver(client, db_session_factory):
    await client.get("/settings?tab=security")
    response = await client.post(
        "/settings/sign-in-policy",
        data=_policy_form(client, login_allowed_networks="203.0.113.0/24"),
    )

    assert response.status_code == 200
    assert "lock you out" in response.text
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).login_allowed_networks is None


async def test_requests_from_outside_the_allowed_networks_are_blocked(client, db_session_factory):
    await _set_settings(db_session_factory, login_allowed_networks="203.0.113.0/24")

    page = await client.get("/dashboard")
    api = await client.get("/api/v1/honeypots")
    health = await client.get("/healthz")

    assert page.status_code == 403
    assert "not allowed" in page.text
    assert api.status_code == 403
    assert health.status_code == 200


async def test_lockout_threshold_comes_from_settings(db_session_factory):
    await _set_settings(db_session_factory, login_max_failed_attempts=2)
    await create_local_user(db_session_factory, username="locky", password="correct-horse-1")

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        for _ in range(2):
            await check_password(db, app_settings, "locky", "wrong")
        user = (await db.execute(select(User).where(User.username == "locky"))).scalar_one()
        assert user.locked_until is not None


async def test_settings_api_reports_the_policy(client, login_as, db_session_factory):
    await _set_settings(db_session_factory, login_allowed_networks="127.0.0.0/8\n10.0.0.0/8")
    user = await login_as(
        client, username="api-admin", is_superadmin=True, api_access_enabled=True
    )
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)

    response = await client.get(
        "/api/v1/settings", headers={"Authorization": f"Bearer {raw_token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["login_max_failed_attempts"] == 5
    assert body["login_allowed_networks"] == ["127.0.0.0/8", "10.0.0.0/8"]
