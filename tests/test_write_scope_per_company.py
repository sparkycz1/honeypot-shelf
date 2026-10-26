"""An account that writes one company and only reads another must not
change the second company's honeypots — on any route, web or API.

`require_write` only says "may write somewhere"; every honeypot action
also has to check *this* honeypot (`can_write_honeypot`). Before 0.83.3
most single-honeypot actions (power, updates, OpenCanary config, read-only
root, logs, terminal page, delete, ...) and the company-wide and bulk ones
only checked that the honeypot was visible."""

from __future__ import annotations

from typing import Any

import pytest

from app.auth.api_tokens import create_api_token
from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.user import AccessLevel, User
from tests.conftest import create_company

_FINGERPRINT = "SHA256:dGVzdC1maW5nZXJwcmludA"


async def _setup(client: Any, login_as: Any, db_session_factory: Any) -> dict[str, Any]:
    own = await create_company(db_session_factory, name="Own")
    other = await create_company(db_session_factory, name="Other")
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, other.id)],
            name="other-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint=_FINGERPRINT,
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    user = await login_as(
        client,
        username="mixed",
        company_id=own.id,
        access_level=AccessLevel.READ_WRITE,
        api_access_enabled=True,
    )
    async with db_session_factory() as db:
        db.add(
            CompanyMembership(user_id=user.id, company_id=other.id, access_level=AccessLevel.READ)
        )
        await db.commit()
        _token, raw = await create_api_token(
            db, await db.get(User, user.id), name="t", expires_at=None
        )
    page = await client.get("/honeypots")
    csrf = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    return {
        "honeypot": honeypot,
        "other": other,
        "csrf": csrf,
        "auth": {"Authorization": f"Bearer {raw}"},
    }


_WEB_POSTS = [
    ("power", {"action": "reboot", "confirm_name": "other-honey1"}),
    ("delete", {"confirm_name": "other-honey1"}),
    ("check-updates", {}),
    ("updates", {"strategy": "upgrade"}),
    ("updates/hold", {"package": "openssl", "hold": "true"}),
    ("refresh-facts", {}),
    ("refresh-packages", {}),
    ("test-connection", {}),
    ("discover-host-key", {}),
    ("run-onboarding", {}),
    ("monitoring/refresh", {}),
    ("status/refresh", {}),
    ("config/modules", {}),
    ("config/readonly", {"enable": "true"}),
    (
        "edit",
        {
            "name": "renamed",
            "ip_address": "192.0.2.10",
            "port": "22",
            "username": "x",
            "auth_method": "ssh_key",
        },
    ),
]

_WEB_GETS = ["config", "terminal", "logs", "edit", "updates", "updates/preview"]


@pytest.mark.parametrize(("path", "data"), _WEB_POSTS, ids=[p for p, _ in _WEB_POSTS])
async def test_web_actions_on_a_read_only_honeypot_are_refused(
    client: Any,
    login_as: Any,
    db_session_factory: Any,
    celery_calls: Any,
    path: str,
    data: dict[str, str],
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    response = await client.post(
        f"/honeypots/{ctx['honeypot'].id}/{path}", data={"csrf_token": ctx["csrf"], **data}
    )
    assert response.status_code == 403, response.text[:300]
    assert list(celery_calls) == []
    async with db_session_factory() as db:
        assert (await db.get(Honeypot, ctx["honeypot"].id)).name == "other-honey1"


@pytest.mark.parametrize("path", _WEB_GETS)
async def test_web_write_pages_of_a_read_only_honeypot_are_refused(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any, path: str
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    response = await client.get(f"/honeypots/{ctx['honeypot'].id}/{path}")
    assert response.status_code == 403
    assert list(celery_calls) == []


async def test_web_bulk_actions_skip_read_only_honeypots(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    hp_id = str(ctx["honeypot"].id)
    await client.post(
        "/honeypots/bulk/power/reboot",
        data={"csrf_token": ctx["csrf"], "honeypot_ids": hp_id, "confirm": "SELECTED HONEYPOTS"},
    )
    await client.post(
        "/honeypots/bulk/check-updates", data={"csrf_token": ctx["csrf"], "honeypot_ids": hp_id}
    )
    await client.post(
        "/honeypots/bulk/delete",
        data={"csrf_token": ctx["csrf"], "honeypot_ids": hp_id, "confirm": "DELETE"},
    )
    assert list(celery_calls) == []
    async with db_session_factory() as db:
        assert await db.get(Honeypot, ctx["honeypot"].id) is not None


_API_CALLS = [
    ("post", "power", {"action": "reboot", "confirm_name": "other-honey1"}),
    ("delete", "", {"confirm_name": "other-honey1"}),
    ("put", "", {"name": "renamed", "ip_address": "192.0.2.10", "port": 22,
                 "username": "x", "auth_method": "ssh_key", "company_ids": []}),
    ("post", "updates", {"strategy": "upgrade"}),
    ("post", "check-updates", None),
    ("post", "refresh-facts", None),
    ("post", "refresh-services", None),
    ("post", "test-connection", None),
    ("post", "packages/openssl/hold", None),
    ("get", "logs", None),
    ("get", "updates/preview", None),
]


@pytest.mark.parametrize(
    ("method", "path", "body"), _API_CALLS, ids=[f"{m} {p}" for m, p, _ in _API_CALLS]
)
async def test_api_actions_on_a_read_only_honeypot_are_refused(
    client: Any,
    login_as: Any,
    db_session_factory: Any,
    celery_calls: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    url = f"/api/v1/honeypots/{ctx['honeypot'].id}" + (f"/{path}" if path else "")
    kwargs: dict[str, Any] = {"headers": ctx["auth"]}
    if body is not None:
        kwargs["json"] = body
    response = await client.request(method.upper(), url, **kwargs)
    assert response.status_code == 403, response.text[:300]
    assert list(celery_calls) == []


async def test_api_company_wide_and_bulk_actions_leave_read_only_honeypots_alone(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    auth = ctx["auth"]
    company_power = await client.post(
        f"/api/v1/companies/{ctx['other'].id}/power",
        json={"action": "reboot", "confirm_name": "Other"},
        headers=auth,
    )
    assert company_power.status_code == 403
    company_updates = await client.post(
        f"/api/v1/companies/{ctx['other'].id}/updates", json={"strategy": "upgrade"}, headers=auth
    )
    assert company_updates.status_code == 403
    await client.post(
        "/api/v1/companies/all/power",
        json={"action": "reboot", "confirm": "ALL HONEYPOTS"},
        headers=auth,
    )
    await client.post(
        "/api/v1/honeypots/bulk/power",
        json={
            "honeypot_ids": [str(ctx["honeypot"].id)],
            "action": "reboot",
            "confirm": "SELECTED HONEYPOTS",
        },
        headers=auth,
    )
    await client.post(
        "/api/v1/honeypots/bulk/tags/add",
        json={"honeypot_ids": [str(ctx["honeypot"].id)], "tags": ["x"]},
        headers=auth,
    )
    assert list(celery_calls) == []
    async with db_session_factory() as db:
        honeypot = await db.get(Honeypot, ctx["honeypot"].id)
        assert [t.name for t in honeypot.tags] == []


async def test_the_same_account_still_manages_its_own_company(
    client: Any, login_as: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    """The fix narrows, it doesn't lock out: a honeypot of the company the
    account writes still takes a power action."""
    ctx = await _setup(client, login_as, db_session_factory)
    async with db_session_factory() as db:
        own = (
            await db.execute(
                Company.__table__.select().where(Company.name == "Own")
            )
        ).one()
        mine = Honeypot(
            companies=[await db.get(Company, own.id)],
            name="own-honey1",
            ip_address="192.0.2.11",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint=_FINGERPRINT,
        )
        db.add(mine)
        await db.commit()
        await db.refresh(mine)
    response = await client.post(
        f"/api/v1/honeypots/{mine.id}/power",
        json={"action": "reboot", "confirm_name": "own-honey1"},
        headers=ctx["auth"],
    )
    assert response.status_code == 200, response.text
    assert [name for name, _a, _k in celery_calls] == [
        "app.tasks.jobs.send_honeypot_power_command"
    ]


async def test_overview_of_a_read_only_honeypot_hides_the_write_tabs_and_buttons(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    ctx = await _setup(client, login_as, db_session_factory)
    page = await client.get(f"/honeypots/{ctx['honeypot'].id}")
    assert page.status_code == 200
    base = f"/honeypots/{ctx['honeypot'].id}"
    for hidden in (f"{base}/terminal", f"{base}/config", f"{base}/power/reboot", "test-connection"):
        assert hidden not in page.text
    assert f"{base}/monitoring" in page.text
