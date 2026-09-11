"""Company CRUD — superadmin-only. Both `Honeypot` and `User` relate to
`Company` many-to-many now — deleting a company only ever detaches them
(removes the link row), never deletes the honeypot or user account
itself (see app/web/routes/companies.py's module/route docstrings)."""

from __future__ import annotations

import re

import pytest

from app.db.models.company import Company
from app.db.models.company_membership import CompanyMembership
from app.db.models.honeypot import Honeypot
from app.db.models.user import AccessLevel, AuthProvider, User

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


async def test_deleting_a_company_detaches_its_honeypots_without_deleting_them(
    client, db_session_factory
):
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        honeypot = Honeypot(companies=[company], name="acme-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(company)
        honeypot_id = honeypot.id

    detail = await client.get(f"/companies/{company.id}")
    response = await client.post(
        f"/companies/{company.id}/delete", data={"csrf_token": _csrf_from(detail)}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await db.get(Company, company.id) is None
        surviving = await db.get(Honeypot, honeypot_id)
        assert surviving is not None
        assert surviving.companies == []


async def test_deleting_a_company_removes_membership_without_deleting_the_user(
    client, db_session_factory
):
    """Regression guard for a real bug: `User.company_id`'s old FK was
    `ondelete=RESTRICT`, so deleting a company that still had users on it
    used to raise an uncaught IntegrityError (a 500). Now that membership
    is its own row (`ondelete=CASCADE`), the delete just removes it —
    still no crash, and now the user survives too."""
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        user = User(
            username="acme-user",
            memberships=[CompanyMembership(company_id=company.id, access_level=AccessLevel.READ)],
            auth_provider=AuthProvider.LOCAL,
        )
        db.add(user)
        await db.commit()
        await db.refresh(company)
        company_id = company.id
        user_id = user.id

    detail = await client.get(f"/companies/{company_id}")
    response = await client.post(
        f"/companies/{company_id}/delete", data={"csrf_token": _csrf_from(detail)}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        assert await db.get(Company, company_id) is None
        surviving = await db.get(User, user_id)
        assert surviving is not None
        assert surviving.memberships == []


async def test_company_detail_shows_users_and_stats(client, db_session_factory):
    """The company page's own users list (with a link to create a brand
    new one) and the honeypot/user stat cards — see the "Company page
    simplified" change."""
    async with db_session_factory() as db:
        company = Company(name="Acme")
        db.add(company)
        await db.flush()
        db.add(Honeypot(companies=[company], name="acme-honey1"))
        db.add(
            User(
                username="acme-user",
                memberships=[
                    CompanyMembership(company_id=company.id, access_level=AccessLevel.READ)
                ],
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


async def test_attach_existing_user_grants_access_without_touching_other_memberships(
    client, db_session_factory
):
    async with db_session_factory() as db:
        company_a = Company(name="Acme")
        company_b = Company(name="Beta")
        db.add_all([company_a, company_b])
        await db.flush()
        user = User(
            username="shared-user",
            memberships=[
                CompanyMembership(company_id=company_a.id, access_level=AccessLevel.READ)
            ],
            auth_provider=AuthProvider.LOCAL,
        )
        db.add(user)
        await db.commit()
        await db.refresh(company_b)
        company_a_id, company_b_id, user_id = company_a.id, company_b.id, user.id

    detail = await client.get(f"/companies/{company_b_id}")
    response = await client.post(
        f"/companies/{company_b_id}/users/attach",
        data={
            "csrf_token": _csrf_from(detail),
            "user_id": str(user_id),
            "access_level": "read_write",
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(User, user_id)
        levels = {m.company_id: m.access_level for m in refreshed.memberships}
        assert levels[company_a_id] == AccessLevel.READ  # untouched
        assert levels[company_b_id] == AccessLevel.READ_WRITE


async def test_attach_existing_honeypot_adds_a_second_company_without_detaching_the_first(
    client, db_session_factory
):
    async with db_session_factory() as db:
        company_a = Company(name="Acme")
        company_b = Company(name="Beta")
        db.add_all([company_a, company_b])
        await db.flush()
        honeypot = Honeypot(companies=[company_a], name="shared-honey1")
        db.add(honeypot)
        await db.commit()
        await db.refresh(company_b)
        company_a_id, company_b_id, honeypot_id = company_a.id, company_b.id, honeypot.id

    detail = await client.get(f"/companies/{company_b_id}")
    response = await client.post(
        f"/companies/{company_b_id}/honeypots/attach",
        data={"csrf_token": _csrf_from(detail), "honeypot_id": str(honeypot_id)},
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(Honeypot, honeypot_id)
        company_ids = {c.id for c in refreshed.companies}
        assert company_ids == {company_a_id, company_b_id}


async def test_users_list_filters_by_company(client, db_session_factory):
    async with db_session_factory() as db:
        company_a = Company(name="Acme")
        company_b = Company(name="Beta")
        db.add_all([company_a, company_b])
        await db.flush()
        db.add(User(
            username="acme-user",
            memberships=[
                CompanyMembership(company_id=company_a.id, access_level=AccessLevel.READ)
            ],
            auth_provider=AuthProvider.LOCAL,
        ))
        db.add(User(
            username="beta-user",
            memberships=[
                CompanyMembership(company_id=company_b.id, access_level=AccessLevel.READ)
            ],
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


async def test_all_honeypots_integrations_tab_updates_fleet_syslog_target(
    client, db_session_factory
):
    form = await client.get("/companies/all/integrations")
    assert form.status_code == 200

    response = await client.post(
        "/companies/all/integrations",
        data={
            "csrf_token": _csrf_from(form),
            "syslog_enabled": "1",
            "syslog_host": "siem.fleet.example.com",
            "syslog_port": "6514",
            "syslog_protocol": "tls",
        },
    )
    assert response.status_code == 303

    from app.core.app_settings import get_or_create_app_settings

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.fleet_alert_syslog_enabled is True
        assert app_settings.fleet_alert_syslog_host == "siem.fleet.example.com"
        assert app_settings.fleet_alert_syslog_port == 6514
        assert app_settings.fleet_alert_syslog_protocol.value == "tls"


async def test_all_honeypots_page_no_longer_has_bulk_update_or_power_sections(client):
    response = await client.get("/companies/all")
    assert response.status_code == 200
    assert "/companies/all/updates" not in response.text
    assert "/companies/all/power" not in response.text


async def test_all_honeypots_integrations_is_superadmin_only(
    anonymous_client, login_as, db_session_factory
):
    from app.db.models.user import AccessLevel
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    await login_as(
        anonymous_client, company_id=company.id, access_level=AccessLevel.READ_WRITE
    )

    response = await anonymous_client.get("/companies/all/integrations")
    assert response.status_code == 403
