"""The Map page (`GET /map`) — company-scoped aggregation of
`HoneypotEvent`'s geo columns (see `app.services.geoip`'s module docstring
for why those are resolved once, at ingestion, rather than looked up here).
Seeds events with their geo columns set directly, rather than going through
a real GeoIP lookup — that logic is `tests/test_geoip.py`'s job."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import AccessLevel
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _create_honeypot(db_session_factory, company_id, name="acme-honey1") -> Honeypot:
    async with db_session_factory() as db:
        company = await db.get(Company, company_id)
        honeypot = Honeypot(
            companies=[company],
            name=name,
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
    return honeypot


async def _add_located_event(
    db_session_factory,
    honeypot_id,
    *,
    country_code="US",
    country_name="United States",
    city_name="Mountain View",
    lat=37.4,
    lon=-122.1,
) -> None:
    async with db_session_factory() as db:
        db.add(
            HoneypotEvent(
                honeypot_id=honeypot_id,
                event_type="SSH_LOGIN_ATTEMPT",
                occurred_at=datetime.now(UTC),
                src_ip="8.8.8.8",
                raw={},
                src_country_code=country_code,
                src_country_name=country_name,
                src_city_name=city_name,
                src_latitude=lat,
                src_longitude=lon,
            )
        )
        await db.commit()


async def test_map_shows_not_ready_hint_when_geoip_never_downloaded(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_honeypot(db_session_factory, company.id)
    await _add_located_event(db_session_factory, honeypot.id)

    response = await client.get("/map")
    assert response.status_code == 200
    assert "isn&#39;t set up yet" in response.text or "isn't set up yet" in response.text


async def test_map_plots_a_located_event_once_geoip_database_exists(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_honeypot(db_session_factory, company.id)
    await _add_located_event(db_session_factory, honeypot.id)

    async with db_session_factory() as db:
        from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

        db.add(GeoipDatabase(id=SINGLETON_ID, mmdb_data=b"fake", source="primary"))
        await db.commit()

    response = await client.get("/map")
    assert response.status_code == 200
    assert "United States" in response.text
    assert "world-map-dot" in response.text


async def test_map_top_countries_counts_events_per_country(client, db_session_factory):
    company = await create_company(db_session_factory)
    honeypot = await _create_honeypot(db_session_factory, company.id)
    for _ in range(3):
        await _add_located_event(
            db_session_factory, honeypot.id, country_code="US", country_name="United States"
        )
    await _add_located_event(
        db_session_factory, honeypot.id, country_code="DE", country_name="Germany",
        city_name="Berlin", lat=52.5, lon=13.4,
    )

    async with db_session_factory() as db:
        from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

        db.add(GeoipDatabase(id=SINGLETON_ID, mmdb_data=b"fake", source="primary"))
        await db.commit()

    response = await client.get("/map")
    assert response.status_code == 200
    # Both country names also appear once in the map's own <title> dot
    # tooltips, above the table - so only look at the table itself,
    # everything from the heading onward.
    table_text = response.text[response.text.index("Top countries") :]
    us_index = table_text.index("United States")
    de_index = table_text.index("Germany")
    # US (3 events) sorts above Germany (1 event) in the top-countries table.
    assert us_index < de_index


async def test_map_excludes_events_from_a_company_the_user_cannot_see(
    client, login_as, db_session_factory
):
    own_company = await create_company(db_session_factory, name="Own Co")
    other_company = await create_company(db_session_factory, name="Other Co")
    own_honeypot = await _create_honeypot(db_session_factory, own_company.id, name="own-honey")
    other_honeypot = await _create_honeypot(
        db_session_factory, other_company.id, name="other-honey"
    )
    await _add_located_event(
        db_session_factory, own_honeypot.id, country_code="US", country_name="United States"
    )
    await _add_located_event(
        db_session_factory, other_honeypot.id, country_code="DE", country_name="Germany",
        city_name="Berlin", lat=52.5, lon=13.4,
    )

    async with db_session_factory() as db:
        from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

        db.add(GeoipDatabase(id=SINGLETON_ID, mmdb_data=b"fake", source="primary"))
        await db.commit()

    await login_as(client, company_id=own_company.id, access_level=AccessLevel.READ)
    response = await client.get("/map")

    assert response.status_code == 200
    assert "United States" in response.text
    assert "Germany" not in response.text
