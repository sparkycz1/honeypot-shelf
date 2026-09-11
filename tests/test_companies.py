"""Company CRUD — superadmin-only. Deleting a company cascades to delete
its honeypots (no "orphan the honeypots" option here, unlike debcontrol's
optional machine-group membership — see app/web/routes/companies.py)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot

pytestmark = pytest.mark.asyncio


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def test_create_company(client):
    new_form = await client.get("/companies/new")
    response = await client.post(
        "/companies",
        data={"name": "Acme Corp", "notes": "Test", "csrf_token": _csrf_from(new_form)},
    )
    assert response.status_code == 303


async def test_deleting_a_company_deletes_its_honeypots(client, db_session_factory):
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        db.add(Honeypot(company_id=company.id, name="acme-honey1"))
        await db.commit()
        await db.refresh(company)

    detail = await client.get(f"/companies/{company.id}")
    response = await client.post(
        f"/companies/{company.id}/delete", data={"csrf_token": _csrf_from(detail)}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await db.get(Company, company.id) is None
        result = await db.execute(select(Honeypot))
        assert result.scalars().all() == []


async def test_deleting_a_company_deletes_its_users_too(client, db_session_factory):
    """Regression guard for a real bug: `User.company_id`'s FK is
    `ondelete=RESTRICT` (deliberately — see app/web/routes/companies.py's
    own comment), so deleting a company that still has users on it used
    to raise an uncaught IntegrityError (a 500) instead of deleting them
    along with it — every company-scoped user requires a company
    (`User`'s own CheckConstraint), so there's no "unassign" option to
    fall back to, the same way a honeypot has none either."""
    from app.db.models.user import AccessLevel, AuthProvider, User

    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        db.add(
            User(
                username="acme-user",
                company_id=company.id,
                access_level=AccessLevel.READ,
                auth_provider=AuthProvider.LOCAL,
            )
        )
        await db.commit()
        await db.refresh(company)
        company_id = company.id

    detail = await client.get(f"/companies/{company_id}")
    response = await client.post(
        f"/companies/{company_id}/delete", data={"csrf_token": _csrf_from(detail)}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await db.get(Company, company_id) is None
        result = await db.execute(select(User).where(User.company_id == company_id))
        assert result.scalars().all() == []


async def test_company_detail_shows_users_and_stats(client, db_session_factory):
    """The company page's own users list (with an "Add user" link) and the
    honeypot/user stat cards — see the "Company page simplified" change."""
    from app.db.models.user import AccessLevel, AuthProvider, User

    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        db.add(Honeypot(company_id=company.id, name="acme-honey1"))
        db.add(
            User(
                username="acme-user",
                company_id=company.id,
                access_level=AccessLevel.READ,
                auth_provider=AuthProvider.LOCAL,
            )
        )
        await db.commit()
        await db.refresh(company)

    response = await client.get(f"/companies/{company.id}")
    assert response.status_code == 200
    assert "acme-user" in response.text
    assert "acme-honey1" in response.text
    assert f'href="/users/new?company_id={company.id}"' in response.text
    assert f'href="/honeypots/new?company_id={company.id}"' in response.text
    # The "Updates"/"Power" tabs were removed from a single company's page.
    assert f'/companies/{company.id}/updates"' not in response.text
    assert f'/companies/{company.id}/power"' not in response.text


async def test_users_list_filters_by_company(client, db_session_factory):
    from app.db.models.user import AccessLevel, AuthProvider, User

    async with db_session_factory() as db:
        company_a = Company(name="Acme")
        company_b = Company(name="Beta")
        db.add_all([company_a, company_b])
        await db.flush()
        db.add(User(
            username="acme-user",
            company_id=company_a.id,
            access_level=AccessLevel.READ,
            auth_provider=AuthProvider.LOCAL,
        ))
        db.add(User(
            username="beta-user",
            company_id=company_b.id,
            access_level=AccessLevel.READ,
            auth_provider=AuthProvider.LOCAL,
        ))
        await db.commit()
        await db.refresh(company_a)

    response = await client.get("/users", params={"company_id": str(company_a.id)})
    assert response.status_code == 200
    assert "acme-user" in response.text
    assert "beta-user" not in response.text


async def test_company_integrations_tab_updates_syslog_target(client, db_session_factory):
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    form = await client.get(f"/companies/{company.id}/integrations")
    assert form.status_code == 200

    response = await client.post(
        f"/companies/{company.id}/integrations",
        data={
            "csrf_token": _csrf_from(form),
            "syslog_enabled": "1",
            "syslog_host": "siem.acme.example.com",
            "syslog_port": "6514",
            "syslog_protocol": "tls",
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(Company, company.id)
        assert refreshed is not None
        assert refreshed.syslog_enabled is True
        assert refreshed.syslog_host == "siem.acme.example.com"
        assert refreshed.syslog_port == 6514
        assert refreshed.syslog_protocol.value == "tls"


async def test_company_integrations_enabled_without_host_is_rejected(
    client, db_session_factory
):
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    form = await client.get(f"/companies/{company.id}/integrations")

    response = await client.post(
        f"/companies/{company.id}/integrations",
        data={
            "csrf_token": _csrf_from(form),
            "syslog_enabled": "1",
            "syslog_host": "",
            "syslog_port": "514",
            "syslog_protocol": "udp",
        },
    )
    assert response.status_code == 200
    assert "server host" in response.text.lower() or "host/ip" in response.text.lower()

    async with db_session_factory() as db:
        refreshed = await db.get(Company, company.id)
        assert refreshed is not None
        assert refreshed.syslog_enabled is False


async def test_company_integrations_is_superadmin_only(
    anonymous_client, login_as, db_session_factory
):
    from app.db.models.user import AccessLevel
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    await login_as(
        anonymous_client, company_id=company.id, access_level=AccessLevel.READ_WRITE
    )

    response = await anonymous_client.get(f"/companies/{company.id}/integrations")
    assert response.status_code == 403
