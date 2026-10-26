"""`/api/v1/companies/{id}/users|honeypots|syslog` and `/companies/all/
syslog` — superadmin-only, additive links, never deleting an account or
a honeypot."""

from __future__ import annotations

from typing import Any

from app.auth.api_tokens import create_api_token
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company


async def _token(db_session_factory: Any, user_id: Any) -> dict[str, str]:
    async with db_session_factory() as db:
        _t, raw = await create_api_token(
            db, await db.get(User, user_id), name="t", expires_at=None
        )
    return {"Authorization": f"Bearer {raw}"}


async def _setup(client: Any, login_as: Any, db_session_factory: Any) -> dict[str, Any]:
    acme = await create_company(db_session_factory, name="Acme")
    beta = await create_company(db_session_factory, name="Beta")
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, acme.id)],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    member = await login_as(
        client, username="member", company_id=acme.id, access_level=AccessLevel.READ_WRITE,
        api_access_enabled=True,
    )
    admin = await login_as(
        client, username="root-admin", is_superadmin=True, api_access_enabled=True
    )
    return {
        "acme": acme,
        "beta": beta,
        "honeypot": honeypot,
        "member": member,
        "admin": await _token(db_session_factory, admin.id),
        "member_auth": await _token(db_session_factory, member.id),
    }


async def test_grant_change_and_revoke_access(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    url = f"/api/v1/companies/{ctx['beta'].id}/users/{ctx['member'].id}"
    granted = await client.put(url, json={"access_level": "read"}, headers=ctx["admin"])
    assert granted.status_code == 200, granted.text
    changed = await client.put(url, json={"access_level": "read_write"}, headers=ctx["admin"])
    assert changed.json()["access_level"] == "read_write"
    async with db_session_factory() as db:
        from sqlalchemy import select

        rows = (
            await db.execute(
                select(CompanyMembership).where(CompanyMembership.user_id == ctx["member"].id)
            )
        ).scalars().all()
        assert {(r.company_id, r.access_level) for r in rows} == {
            (ctx["acme"].id, AccessLevel.READ_WRITE),
            (ctx["beta"].id, AccessLevel.READ_WRITE),
        }
    assert (await client.delete(url, headers=ctx["admin"])).status_code == 204
    assert (await client.delete(url, headers=ctx["admin"])).status_code == 404
    async with db_session_factory() as db:
        assert await db.get(User, ctx["member"].id) is not None


async def test_attach_and_detach_honeypot_never_deletes_it(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    hp = ctx["honeypot"]
    for company in (ctx["beta"], ctx["acme"]):
        url = f"/api/v1/companies/{company.id}/honeypots/{hp.id}"
        assert (await client.put(url, headers=ctx["admin"])).status_code == 204
    async with db_session_factory() as db:
        assert {c.name for c in (await db.get(Honeypot, hp.id)).companies} == {"Acme", "Beta"}
    for company in (ctx["acme"], ctx["beta"]):
        url = f"/api/v1/companies/{company.id}/honeypots/{hp.id}"
        assert (await client.delete(url, headers=ctx["admin"])).status_code == 204
    async with db_session_factory() as db:
        assert (await db.get(Honeypot, hp.id)).companies == []


async def test_syslog_targets(client: Any, login_as: Any, db_session_factory: Any) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    url = f"/api/v1/companies/{ctx['acme'].id}/syslog"
    missing_host = await client.put(url, json={"enabled": True}, headers=ctx["admin"])
    assert missing_host.status_code == 422
    saved = await client.put(
        url,
        json={"enabled": True, "host": " siem.example.com ", "port": 6514, "protocol": "tcp"},
        headers=ctx["admin"],
    )
    assert saved.status_code == 200, saved.text
    assert (await client.get(url, headers=ctx["admin"])).json() == {
        "enabled": True, "host": "siem.example.com", "port": 6514, "protocol": "tcp"
    }
    fleet = await client.put(
        "/api/v1/companies/all/syslog",
        json={"enabled": False, "host": "", "port": 514},
        headers=ctx["admin"],
    )
    assert fleet.status_code == 200, fleet.text
    assert fleet.json()["enabled"] is False
    assert fleet.json()["host"] is None


async def test_everything_here_is_superadmin_only(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    acme = ctx["acme"].id
    for method, path, body in (
        ("PUT", f"{acme}/users/{ctx['member'].id}", {"access_level": "read_write"}),
        ("DELETE", f"{acme}/users/{ctx['member'].id}", None),
        ("PUT", f"{acme}/honeypots/{ctx['honeypot'].id}", None),
        ("DELETE", f"{acme}/honeypots/{ctx['honeypot'].id}", None),
        ("GET", f"{acme}/syslog", None),
        ("PUT", f"{acme}/syslog", {"enabled": False}),
        ("GET", "all/syslog", None),
    ):
        response = await client.request(
            method, f"/api/v1/companies/{path}", json=body, headers=ctx["member_auth"]
        )
        assert response.status_code == 403, (method, path, response.status_code)
