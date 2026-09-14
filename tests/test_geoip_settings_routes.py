"""Settings → GeoIP (`app.web.routes.settings.update_geoip_settings`/
`refresh_geoip_now`) — saving the enabled flag/URLs/refresh interval, and
the "Download now" button. The actual download/fallback logic is
`tests/test_geoip.py`'s job; these only exercise the route/form layer,
using `tests/conftest.py`'s Celery-call recorder rather than a real
worker."""

from __future__ import annotations

import re

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.core.security import decrypt_secret

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_geoip_tab_renders(client):
    response = await client.get("/settings", params={"tab": "geoip"})
    assert response.status_code == 200
    assert "GeoIP" in response.text


async def test_update_geoip_settings_saves_urls_encrypted(client, db_session_factory):
    form = await client.get("/settings", params={"tab": "geoip"})
    response = await client.post(
        "/settings/geoip",
        data={
            "csrf_token": _csrf_from(form),
            "geoip_enabled": "on",
            "geoip_primary_url": "https://download.maxmind.com/geoip/databases/GeoLite2-City",
            "geoip_backup_url": "https://backup.example/geolite2-city.mmdb",
            "geoip_refresh_interval_hours": "24",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=geoip"

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.geoip_enabled is True
        assert app_settings.geoip_refresh_interval_hours == 24
        assert app_settings.geoip_primary_url_encrypted is not None
        assert app_settings.geoip_backup_url_encrypted is not None
        assert (
            decrypt_secret(app_settings.geoip_primary_url_encrypted)
            == "https://download.maxmind.com/geoip/databases/GeoLite2-City"
        )
        assert (
            decrypt_secret(app_settings.geoip_backup_url_encrypted)
            == "https://backup.example/geolite2-city.mmdb"
        )


async def test_enabling_geoip_without_any_url_is_rejected(client):
    form = await client.get("/settings", params={"tab": "geoip"})
    response = await client.post(
        "/settings/geoip",
        data={"csrf_token": _csrf_from(form), "geoip_enabled": "on"},
    )
    assert response.status_code == 200
    assert "needs at least a primary" in response.text.lower()


async def test_blank_url_on_a_later_save_keeps_the_existing_one(client, db_session_factory):
    form = await client.get("/settings", params={"tab": "geoip"})
    await client.post(
        "/settings/geoip",
        data={
            "csrf_token": _csrf_from(form),
            "geoip_primary_url": "https://first.example/db",
        },
    )
    form2 = await client.get("/settings", params={"tab": "geoip"})
    await client.post(
        "/settings/geoip",
        data={"csrf_token": _csrf_from(form2), "geoip_refresh_interval_hours": "48"},
    )

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.geoip_refresh_interval_hours == 48
        assert app_settings.geoip_primary_url_encrypted is not None
        assert (
            decrypt_secret(app_settings.geoip_primary_url_encrypted) == "https://first.example/db"
        )


async def test_refresh_now_without_any_url_configured_is_rejected(client):
    form = await client.get("/settings", params={"tab": "geoip"})
    response = await client.post(
        "/settings/geoip/refresh", data={"csrf_token": _csrf_from(form)}
    )
    assert response.status_code == 200
    assert "set a primary" in response.text.lower()


async def test_refresh_now_dispatches_the_download_task(client, db_session_factory, celery_calls):
    form = await client.get("/settings", params={"tab": "geoip"})
    await client.post(
        "/settings/geoip",
        data={"csrf_token": _csrf_from(form), "geoip_primary_url": "https://primary.example/db"},
    )

    form2 = await client.get("/settings", params={"tab": "geoip"})
    response = await client.post(
        "/settings/geoip/refresh", data={"csrf_token": _csrf_from(form2)}, follow_redirects=False
    )

    assert "app.tasks.jobs.refresh_geoip_database" in celery_calls.names
    # celery_calls' default fake result is {"ok": True, ...} - a success.
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=geoip"


async def test_refresh_now_surfaces_a_failed_download(client, celery_calls):
    celery_calls.result_for["app.tasks.jobs.refresh_geoip_database"] = {
        "ok": False,
        "error": "primary: connection refused",
    }
    form = await client.get("/settings", params={"tab": "geoip"})
    await client.post(
        "/settings/geoip",
        data={"csrf_token": _csrf_from(form), "geoip_primary_url": "https://primary.example/db"},
    )

    form2 = await client.get("/settings", params={"tab": "geoip"})
    response = await client.post(
        "/settings/geoip/refresh", data={"csrf_token": _csrf_from(form2)}
    )

    assert response.status_code == 200
    assert "connection refused" in response.text
