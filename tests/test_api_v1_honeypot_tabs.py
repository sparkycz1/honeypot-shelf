"""`/api/v1/honeypots/{id}/monitoring` and `/config...` — the Monitoring
and Config tabs through the API, scoped like the web pages."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_service import HoneypotService
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company

_JOBS = "app.tasks.jobs."


async def _setup(
    client: Any,
    login_as: Any,
    db_session_factory: Any,
    access: AccessLevel = AccessLevel.READ_WRITE,
) -> tuple[dict[str, str], Honeypot]:
    acme = await create_company(db_session_factory, name="Acme")
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, acme.id)],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:dGVzdA",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        now = datetime.now(UTC)
        for minutes, cpu in ((30, 10.0), (10, 30.0)):
            db.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id,
                    sampled_at=now - timedelta(minutes=minutes),
                    cpu_percent=cpu,
                    ram_used_bytes=512,
                    ram_total_bytes=1024,
                )
            )
        db.add(
            HoneypotService(
                honeypot_id=honeypot.id,
                unit="opencanary.service",
                load_state="loaded",
                active_state="active",
                sub_state="running",
                description="OpenCanary",
            )
        )
        await db.commit()
    user = await login_as(
        client,
        username="api-tabs",
        company_id=acme.id,
        access_level=access,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        _token, raw = await create_api_token(
            db, await db.get(User, user.id), name="t", expires_at=None
        )
    return {"Authorization": f"Bearer {raw}"}, honeypot


async def test_monitoring_is_readable_with_read_access(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory, AccessLevel.READ)
    response = await client.get(
        f"/api/v1/honeypots/{honeypot.id}/monitoring?range_key=1h", headers=headers
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["range_key"] == "1h"
    assert body["history"]["sample_count"] == 2
    assert body["history"]["latest_cpu_percent"] == 30.0
    assert body["services"][0]["unit"] == "opencanary.service"
    # ...but "Refresh now" is a write action.
    refresh = await client.post(
        f"/api/v1/honeypots/{honeypot.id}/monitoring/refresh", headers=headers
    )
    assert refresh.status_code == 403


async def test_monitoring_refresh_runs_the_three_checks(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory)
    response = await client.post(
        f"/api/v1/honeypots/{honeypot.id}/monitoring/refresh", headers=headers
    )
    assert response.status_code == 200, response.text
    assert response.json()["error"] is None
    assert sorted(name for name, _a, _k in celery_calls) == [
        _JOBS + "check_honeypot_reachability",
        _JOBS + "refresh_honeypot_services",
        _JOBS + "sample_honeypot_monitoring",
    ]


async def test_config_lists_settings_and_patch_changes_only_what_was_sent(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory)
    celery_calls.result_for[_JOBS + "read_honeypot_opencanary_config"] = {
        "ok": True,
        "config": {"ftp.enabled": False, "ftp.port": 21, "logger": {"class": "x"}},
    }
    config = await client.get(f"/api/v1/honeypots/{honeypot.id}/config", headers=headers)
    assert config.status_code == 200, config.text
    settings = {s["key"]: s for s in config.json()["opencanary"]}
    assert settings["ftp.enabled"] == {
        "key": "ftp.enabled", "module": "ftp", "type": "bool", "value": False
    }
    assert settings["ftp.port"]["value"] == 21

    saved = await client.patch(
        f"/api/v1/honeypots/{honeypot.id}/config/opencanary",
        json={"settings": {"ftp.enabled": True, "ftp.port": 2121}},
        headers=headers,
    )
    assert saved.status_code == 200, saved.text
    write_args = next(
        a for n, a, _k in celery_calls if n == _JOBS + "write_honeypot_opencanary_config"
    )
    assert write_args[1] == {"ftp.enabled": True, "ftp.port": 2121, "logger": {"class": "x"}}
    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot.id)
        assert "ftp" in [t.name for t in refreshed.tags]
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
        assert "honeypot.opencanary_config.save" in actions


async def test_patch_rejects_unknown_keys_and_wrong_types(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory)
    response = await client.patch(
        f"/api/v1/honeypots/{honeypot.id}/config/opencanary",
        json={"settings": {"logger": {}, "ftp.port": "21", "ftp.enabled": 1}},
        headers=headers,
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert len(detail) == 3
    assert not [n for n, _a, _k in celery_calls if "write" in n]


async def test_config_needs_write_access(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory, AccessLevel.READ)
    for method, path, body in (
        ("GET", "config", None),
        ("PATCH", "config/opencanary", {"settings": {"ftp.enabled": True}}),
        ("PUT", "config/readonly", {"enable": True}),
        ("GET", "config/mac", None),
        ("PUT", "config/mac", {"mac_address": "00:1b:63:84:45:e6"}),
        ("DELETE", "config/mac", None),
    ):
        response = await client.request(
            method, f"/api/v1/honeypots/{honeypot.id}/{path}", json=body, headers=headers
        )
        assert response.status_code == 403, (method, path, response.status_code)


async def test_mac_address_set_and_reset(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory)
    celery_calls.result_for[_JOBS + "honeypot_mac_address"] = {
        "ok": True,
        "current": "dc:a6:32:00:00:01",
        "configured": "00:1b:63:84:45:e6",
    }
    bad = await client.put(
        f"/api/v1/honeypots/{honeypot.id}/config/mac",
        json={"mac_address": "not-a-mac"},
        headers=headers,
    )
    assert bad.status_code == 422
    ok = await client.put(
        f"/api/v1/honeypots/{honeypot.id}/config/mac",
        json={"mac_address": "00-1B-63-84-45-E6"},
        headers=headers,
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["configured"] == "00:1b:63:84:45:e6"
    reset = await client.delete(f"/api/v1/honeypots/{honeypot.id}/config/mac", headers=headers)
    assert reset.status_code == 200
    calls = [k for n, _a, k in celery_calls if n == _JOBS + "honeypot_mac_address"]
    assert calls[0]["mac"] == "00:1b:63:84:45:e6"
    assert calls[1] == {"reset": True}


async def test_readonly_toggle_refused_without_raspi_config(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    headers, honeypot = await _setup(client, login_as, db_session_factory)
    response = await client.put(
        f"/api/v1/honeypots/{honeypot.id}/config/readonly",
        json={"enable": True},
        headers=headers,
    )
    assert response.status_code == 409
    assert list(celery_calls) == []
