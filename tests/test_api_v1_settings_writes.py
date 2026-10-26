"""`/api/v1/settings/checks|retention|geoip|mac-vendors` — the writable
parts of Settings, superadmin-only, same bounds as the page."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company


async def _auth(client: Any, login_as: Any, db_session_factory: Any, **kwargs: Any) -> Any:
    user = await login_as(client, api_access_enabled=True, **kwargs)
    async with db_session_factory() as db:
        _t, raw = await create_api_token(
            db, await db.get(User, user.id), name="t", expires_at=None
        )
    return {"Authorization": f"Bearer {raw}"}


async def _actions(db_session_factory: Any) -> list[str]:
    async with db_session_factory() as db:
        return list((await db.execute(select(AuditLogEntry.action))).scalars())


async def test_checks_partial_update_and_bounds(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers = await _auth(client, login_as, db_session_factory, username="a", is_superadmin=True)
    before = (await client.get("/api/v1/settings/checks", headers=headers)).json()
    response = await client.patch(
        "/api/v1/settings/checks", json={"monitoring_interval_seconds": 120}, headers=headers
    )
    assert response.status_code == 200, response.text
    assert response.json() == {**before, "monitoring_interval_seconds": 120}
    too_low = await client.patch(
        "/api/v1/settings/checks", json={"ssh_connect_timeout": 0}, headers=headers
    )
    assert too_low.status_code == 422
    null = await client.patch(
        "/api/v1/settings/checks", json={"ssh_connect_timeout": None}, headers=headers
    )
    assert null.status_code == 422
    assert "settings.checks.update" in await _actions(db_session_factory)


async def test_retention_null_means_forever_and_each_change_is_audited(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers = await _auth(client, login_as, db_session_factory, username="a", is_superadmin=True)
    response = await client.patch(
        "/api/v1/settings/retention",
        json={"audit_log_retention_days": None, "event_retention_days": 30},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["audit_log_retention_days"] is None
    assert body["event_retention_days"] == 30
    assert body["event_retention_days_effective"] == 30
    actions = await _actions(db_session_factory)
    assert "settings.audit_retention.update" in actions
    assert "settings.event_retention.update" in actions
    assert "settings.monitoring_retention.update" not in actions
    zero_events = await client.patch(
        "/api/v1/settings/retention", json={"event_retention_days": 0}, headers=headers
    )
    assert zero_events.status_code == 422


async def test_geoip_urls_are_write_only_and_kept_when_omitted(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers = await _auth(client, login_as, db_session_factory, username="a", is_superadmin=True)
    needs_url = await client.put("/api/v1/settings/geoip", json={"enabled": True}, headers=headers)
    assert needs_url.status_code == 422
    secret_url = "https://download.example.com/geoip?license_key=SECRET123"
    saved = await client.put(
        "/api/v1/settings/geoip",
        json={"enabled": True, "primary_url": secret_url, "refresh_interval_hours": 24},
        headers=headers,
    )
    assert saved.status_code == 200, saved.text
    assert "SECRET123" not in saved.text
    assert saved.json()["has_primary_url"] is True
    again = await client.put(
        "/api/v1/settings/geoip", json={"enabled": False}, headers=headers
    )
    assert again.json()["has_primary_url"] is True
    async with db_session_factory() as db:
        settings = (await db.execute(select(AppSettings))).scalar_one()
        assert b"SECRET123" not in (settings.geoip_primary_url_encrypted or b"")


async def test_mac_vendor_list_url_must_be_public(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers = await _auth(client, login_as, db_session_factory, username="a", is_superadmin=True)
    private = await client.put(
        "/api/v1/settings/mac-vendors",
        json={"list_url": "http://127.0.0.1/oui.txt"},
        headers=headers,
    )
    assert private.status_code == 422
    off = await client.put(
        "/api/v1/settings/mac-vendors",
        json={"list_url": None, "refresh_interval_hours": 48},
        headers=headers,
    )
    assert off.status_code == 200, off.text
    assert off.json()["list_url"] is None
    assert off.json()["refresh_interval_hours"] == 48


async def test_settings_writes_are_superadmin_only(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    acme = await create_company(db_session_factory, name="Acme")
    headers = await _auth(
        client, login_as, db_session_factory, username="rw",
        company_id=acme.id, access_level=AccessLevel.READ_WRITE,
    )
    for method, path, body in (
        ("PATCH", "checks", {"ssh_connect_timeout": 10}),
        ("PATCH", "retention", {"audit_log_retention_days": 1}),
        ("PUT", "geoip", {"enabled": False}),
        ("POST", "geoip/refresh", None),
        ("PUT", "mac-vendors", {"list_url": None}),
        ("POST", "mac-vendors/refresh", None),
    ):
        response = await client.request(
            method, f"/api/v1/settings/{path}", json=body, headers=headers
        )
        assert response.status_code == 403, (method, path, response.status_code)
