"""Fixes from the 0.84.1 review of the REST API: company-limited tokens
stay inside their companies for write access, Initialize and notification
rules, and a few API answers that were wrong or too revealing."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import Honeypot
from app.db.models.initialize_run import InitializeRun
from app.db.models.notification_channel import NotificationChannel
from app.db.models.notification_log import NotificationKind, NotificationLog
from app.db.models.user import AuthProvider, User
from app.web.routes import api_v1_initialize, initialize_ws
from app.web.routes.initialize import PendingInitializeRun
from tests.conftest import create_company

_INITIALIZE = {
    "ip_address": "192.0.2.50",
    "device_name": "acme-honey9",
    "username": "pi",
    "auth_method": "password",
    "password": "device-secret-pw",
}


async def _fleet(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    """Two companies with one honeypot each: (atlas, borealis, atlas
    honeypot, borealis honeypot)."""
    atlas = await create_company(db_session_factory, name="Atlas")
    borealis = await create_company(db_session_factory, name="Borealis")
    async with db_session_factory() as db:
        atlas_row = await db.get(Company, atlas.id)
        borealis_row = await db.get(Company, borealis.id)
        first = Honeypot(companies=[atlas_row], name="atlas-honey")
        second = Honeypot(companies=[borealis_row], name="borealis-honey")
        db.add_all([first, second])
        await db.commit()
        return atlas.id, borealis.id, first.id, second.id


async def _token(db_session_factory: Any, user_id: Any, **limits: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        _t, raw = await create_api_token(db, user, name="t", expires_at=None, **limits)
    return {"Authorization": f"Bearer {raw}"}


def test_can_write_counts_only_the_tokens_companies() -> None:
    atlas, borealis = uuid.uuid4(), uuid.uuid4()
    user = User(
        username="member",
        is_superadmin=False,
        memberships=[
            CompanyMembership(company_id=atlas, access_level=AccessLevel.READ_WRITE),
            CompanyMembership(company_id=borealis, access_level=AccessLevel.READ),
        ],
    )
    assert user.can_write()
    user.token_company_scope = frozenset({borealis})
    assert not user.can_write()
    user.token_company_scope = frozenset({atlas})
    assert user.can_write()

    admin = User(username="admin", is_superadmin=True, memberships=[])
    admin.token_company_scope = frozenset()
    assert not admin.can_write()
    admin.token_company_scope = frozenset({atlas})
    assert admin.can_write()


async def test_token_limited_to_a_read_only_company_cannot_write(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, borealis_id, _a, _b = await _fleet(db_session_factory)
    user = await login_as(
        client,
        username="member",
        company_id=atlas_id,
        access_level=AccessLevel.READ_WRITE,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        db.add(
            CompanyMembership(
                user_id=user.id, company_id=borealis_id, access_level=AccessLevel.READ
            )
        )
        await db.commit()

    headers = await _token(db_session_factory, user.id, company_ids=[borealis_id])
    refused = await client.post("/api/v1/initialize", json=_INITIALIZE, headers=headers)
    assert refused.status_code == 403
    assert refused.json()["detail"] == "This API token's account has read-only access."


async def test_company_limited_tokens_cannot_use_initialize(
    client: Any, login_as: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[PendingInitializeRun] = []

    async def fake_run(run: PendingInitializeRun, user: User, factory: Any, emit: Any) -> None:
        started.append(run)

    monkeypatch.setattr(initialize_ws, "run_initialize", fake_run)
    atlas_id, _borealis, _a, _b = await _fleet(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)

    limited = await _token(db_session_factory, user.id, company_ids=[atlas_id])
    for method, path in (
        ("POST", "/api/v1/initialize"),
        ("GET", "/api/v1/initialize/history"),
    ):
        response = await client.request(
            method, path, json=_INITIALIZE if method == "POST" else None, headers=limited
        )
        assert response.status_code == 403, path
        assert response.json()["detail"] == "This API token is limited to some companies."
    assert started == []

    unlimited = await _token(db_session_factory, user.id)
    assert (await client.get("/api/v1/initialize/history", headers=unlimited)).status_code == 200


def _rule(name: str, company_id: uuid.UUID) -> dict[str, object]:
    return {
        "name": name,
        "scope": "company",
        "company_ids": [str(company_id)],
        "notify_on_alert": True,
        "target_email": "soc@example.com",
    }


async def test_company_limited_token_keeps_to_its_companies_in_notifications(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, borealis_id, atlas_hp, borealis_hp = await _fleet(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    limited = await _token(db_session_factory, user.id, company_ids=[atlas_id])
    unlimited = await _token(db_session_factory, user.id)

    # A rule about another company: refused like any out-of-scope id.
    refused = await client.post(
        "/api/v1/notifications/rules", json=_rule("b", borealis_id), headers=limited
    )
    assert refused.status_code == 404
    inside = await client.post(
        "/api/v1/notifications/rules", json=_rule("a", atlas_id), headers=limited
    )
    assert inside.status_code == 201, inside.text

    # The owner's own rule about Borealis (made without a limit) stays
    # hidden from the limited token: not listed, not readable, not deletable.
    other = await client.post(
        "/api/v1/notifications/rules", json=_rule("b", borealis_id), headers=unlimited
    )
    assert other.status_code == 201, other.text
    other_id = other.json()["id"]
    listed = await client.get("/api/v1/notifications/rules", headers=limited)
    assert [r["name"] for r in listed.json()] == ["a"]
    all_rules = await client.get("/api/v1/notifications/rules", headers=unlimited)
    assert [r["name"] for r in all_rules.json()] == ["a", "b"]
    for method in ("GET", "DELETE"):
        response = await client.request(
            method, f"/api/v1/notifications/rules/{other_id}", headers=limited
        )
        assert response.status_code == 404
    test_send = await client.post(
        f"/api/v1/notifications/rules/{other_id}/test", headers=limited
    )
    assert test_send.status_code == 404

    # Send history: only the sends about the token's honeypots.
    async with db_session_factory() as db:
        for honeypot_id, name in ((atlas_hp, "atlas-honey"), (borealis_hp, "borealis-honey")):
            db.add(
                NotificationLog(
                    user_id=user.id,
                    honeypot_id=honeypot_id,
                    honeypot_name=name,
                    kind=NotificationKind.ALERT,
                    channel=NotificationChannel.WEBHOOK,
                    target="https://hooks.example.com/x",
                    success=True,
                )
            )
        await db.commit()
    history = await client.get("/api/v1/notifications/history", headers=limited)
    assert [e["honeypot_name"] for e in history.json()] == ["atlas-honey"]
    full = await client.get("/api/v1/notifications/history", headers=unlimited)
    assert sorted(e["honeypot_name"] for e in full.json()) == ["atlas-honey", "borealis-honey"]


async def test_cancelled_initialize_is_recorded_as_a_failure(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def hang(*_args: Any, **_kwargs: Any) -> str:
        await asyncio.sleep(3600)
        return "never"

    monkeypatch.setattr(initialize_ws, "discover_host_key_fingerprint", hang)
    async with db_session_factory() as db:
        user = User(username="starter", auth_provider=AuthProvider.LOCAL, is_superadmin=True)
        db.add(user)
        await db.commit()
        await db.refresh(user)
    run = PendingInitializeRun(
        ip_address="192.0.2.30",
        port=22,
        username="root",
        device_name="acme-honey9",
        auth_method="password",
        password="device-password",
        vpn_provider="none",
        netbird_setup_key=None,
        netbird_management_url=None,
        wireguard_config=None,
        new_ssh_port=22222,
        created_by=user.id,
    )
    frames: list[dict[str, Any]] = []

    async def emit(frame: dict[str, Any]) -> None:
        frames.append(frame)

    task = asyncio.create_task(initialize_ws.run_initialize(run, user, db_session_factory, emit))
    for _ in range(20):
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    done = [f for f in frames if f["kind"] == "done"]
    assert len(done) == 1
    assert done[0]["ok"] is False
    assert done[0]["error"] == "Initialize was interrupted before it finished."
    async with db_session_factory() as db:
        stored = (await db.execute(select(InitializeRun))).scalar_one()
        assert stored.success is False


async def test_initialize_survives_a_settings_failure(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(initialize_ws, "get_or_create_app_settings", broken)
    user = User(id=uuid.uuid4(), username="starter", is_superadmin=True)
    frames: list[dict[str, Any]] = []

    async def emit(frame: dict[str, Any]) -> None:
        frames.append(frame)

    run = PendingInitializeRun(
        ip_address="192.0.2.30",
        port=22,
        username="root",
        device_name="acme-honey9",
        auth_method="ssh_key",
        password=None,
        vpn_provider="none",
        netbird_setup_key=None,
        netbird_management_url=None,
        wireguard_config=None,
        new_ssh_port=22222,
    )
    await initialize_ws.run_initialize(run, user, db_session_factory, emit)
    assert frames[-1]["kind"] == "done"
    assert frames[-1]["ok"] is False


def test_live_run_keeps_only_the_newest_output_lines() -> None:
    live = api_v1_initialize.LiveRun(created_by=uuid.uuid4(), device_name="d", ip_address="i")
    total = api_v1_initialize._MAX_LIVE_OUTPUT_LINES + 3

    async def fill() -> None:
        for n in range(total):
            await live.emit({"kind": "output", "text": f"line {n}"})

    asyncio.run(fill())
    assert live.output_dropped == 3
    assert len(live.output) == api_v1_initialize._MAX_LIVE_OUTPUT_LINES
    assert live.output[0] == "line 3"
    assert live.output[-1] == f"line {total - 1}"
