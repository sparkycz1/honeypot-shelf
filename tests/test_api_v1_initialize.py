"""`/api/v1/initialize` — start a run, follow it, read the history. The
SSH work itself (`initialize_ws.run_initialize`) is replaced by a fake
that emits frames; `tests/test_initialize.py` covers the real runner."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.auth.api_tokens import create_api_token
from app.db.models.initialize_run import InitializeRun
from app.db.models.user import AccessLevel, User
from app.web.routes import api_v1_initialize, initialize_ws
from app.web.routes.initialize import PendingInitializeRun
from tests.conftest import create_company

_REQUEST = {
    "ip_address": "192.0.2.50",
    "device_name": "acme-honey9",
    "username": "pi",
    "auth_method": "password",
    "password": "device-secret-pw",
}


async def _auth(
    client: Any, login_as: Any, db_session_factory: Any, username: str, level: AccessLevel
) -> dict[str, str]:
    company = await create_company(db_session_factory, name=f"Co-{username}")
    user = await login_as(
        client, username=username, company_id=company.id, access_level=level,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        _t, raw = await create_api_token(
            db, await db.get(User, user.id), name="t", expires_at=None
        )
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> list[PendingInitializeRun]:
    started: list[PendingInitializeRun] = []

    async def fake_run(
        run: PendingInitializeRun, user: User, factory: Any, emit: Any
    ) -> None:
        started.append(run)
        await emit({"kind": "step", "label": "Connecting"})
        await emit({"kind": "output", "text": "line one"})
        await emit({"kind": "output", "text": "line two"})
        await emit({"kind": "done", "ok": True, "error": None, "fingerprint": "SHA256:abc"})

    monkeypatch.setattr(initialize_ws, "run_initialize", fake_run)
    api_v1_initialize.LIVE_RUNS.clear()
    return started


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


async def test_start_and_follow_a_run(
    client: Any, login_as: Any, db_session_factory: Any, fake_runner: list[Any]
) -> None:
    headers = await _auth(client, login_as, db_session_factory, "rw", AccessLevel.READ_WRITE)
    started = await client.post("/api/v1/initialize", json=_REQUEST, headers=headers)
    assert started.status_code == 202, started.text
    run_id = started.json()["run_id"]
    await _settle()
    assert fake_runner[0].password == "device-secret-pw"

    status = await client.get(f"/api/v1/initialize/runs/{run_id}", headers=headers)
    assert status.status_code == 200
    body = status.json()
    assert body["done"] is True
    assert body["ok"] is True
    assert body["fingerprint"] == "SHA256:abc"
    assert body["steps"] == ["Connecting"]
    assert body["output"] == ["line one", "line two"]
    assert "device-secret-pw" not in status.text

    later = await client.get(
        f"/api/v1/initialize/runs/{run_id}?since={body['next_since'] - 1}", headers=headers
    )
    assert later.json()["output"] == ["line two"]


async def test_someone_elses_run_is_not_found(
    client: Any, login_as: Any, db_session_factory: Any, fake_runner: list[Any]
) -> None:
    owner = await _auth(client, login_as, db_session_factory, "owner", AccessLevel.READ_WRITE)
    other = await _auth(client, login_as, db_session_factory, "other", AccessLevel.READ_WRITE)
    run_id = (await client.post("/api/v1/initialize", json=_REQUEST, headers=owner)).json()[
        "run_id"
    ]
    await _settle()
    response = await client.get(f"/api/v1/initialize/runs/{run_id}", headers=other)
    assert response.status_code == 404


async def test_validation_and_read_only(
    client: Any, login_as: Any, db_session_factory: Any, fake_runner: list[Any]
) -> None:
    rw = await _auth(client, login_as, db_session_factory, "rw", AccessLevel.READ_WRITE)
    bad = await client.post(
        "/api/v1/initialize",
        json={**_REQUEST, "device_name": "bad;name", "password": None},
        headers=rw,
    )
    assert bad.status_code == 422
    assert len(bad.json()["detail"]) == 2
    ro = await _auth(client, login_as, db_session_factory, "ro", AccessLevel.READ)
    refused = await client.post("/api/v1/initialize", json=_REQUEST, headers=ro)
    assert refused.status_code == 403
    history = await client.get("/api/v1/initialize/history", headers=ro)
    assert history.status_code == 403
    await _settle()
    assert fake_runner == []


async def test_history(client: Any, login_as: Any, db_session_factory: Any) -> None:
    from datetime import UTC, datetime

    headers = await _auth(client, login_as, db_session_factory, "rw", AccessLevel.READ_WRITE)
    async with db_session_factory() as db:
        run = InitializeRun(
            device_name="acme-honey9",
            ip_address="192.0.2.50",
            port=22,
            username="pi",
            started_at=datetime.now(UTC),
            success=False,
            error="Setup script exited 1.",
            output="apt-get failed",
            triggered_by="rw",
        )
        db.add(run)
        await db.commit()
        await db.refresh(run)
    listed = await client.get("/api/v1/initialize/history", headers=headers)
    assert [r["id"] for r in listed.json()] == [str(run.id)]
    assert "output" not in listed.json()[0]
    detail = await client.get(f"/api/v1/initialize/history/{run.id}", headers=headers)
    assert detail.json()["output"] == "apt-get failed"
