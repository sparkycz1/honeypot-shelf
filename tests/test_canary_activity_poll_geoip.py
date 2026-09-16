"""`app.tasks.jobs._poll_honeypot_canary_log`'s GeoIP enrichment — every
newly ingested `HoneypotEvent` gets its `src_*` geo columns filled in from
one shared reader for the whole batch (see `app.services.geoip`'s module
docstring for why this happens once, at ingestion). Monkeypatches
`get_geoip_reader`/`geoip_lookup` directly rather than a real MaxMind
database - same reasoning as `tests/test_geoip.py`."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.services.geoip import GeoLocation
from app.ssh.canary_activity import LogPollResult
from app.tasks.jobs import _poll_honeypot_canary_log
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


async def _make_honeypot(db_session_factory, company_id):
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company_id)],
            name="acme-honey1",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        return honeypot.id


async def test_ingested_events_get_geo_columns_from_a_shared_reader(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot_id = await _make_honeypot(db_session_factory, company.id)

    fake_result = LogPollResult(
        events=[
            {
                "logtype": 4002,
                "local_time": "2026-01-01 12:00:02.000000",
                "src_host": "203.0.113.7",
            },
        ],
        new_offset=1,
    )
    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int, *, path: str = ""
    ):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    sentinel_reader = object()
    lookups: list[str | None] = []

    async def fake_get_reader(db):
        return sentinel_reader

    def fake_lookup(reader, ip_str):
        assert reader is sentinel_reader
        lookups.append(ip_str)
        return GeoLocation(
            country_code="US",
            country_name="United States",
            city_name="Mountain View",
            latitude=37.4,
            longitude=-122.1,
        )

    monkeypatch.setattr("app.tasks.jobs.get_geoip_reader", fake_get_reader)
    monkeypatch.setattr("app.tasks.jobs.geoip_lookup", fake_lookup)

    await _poll_honeypot_canary_log(str(honeypot_id))

    assert lookups == ["203.0.113.7"]
    async with db_session_factory() as db:
        event = (await db.execute(select(HoneypotEvent))).scalars().one()
        assert event.src_country_code == "US"
        assert event.src_country_name == "United States"
        assert event.src_city_name == "Mountain View"
        assert event.src_latitude == 37.4
        assert event.src_longitude == -122.1


async def test_ingested_events_keep_geo_columns_none_when_geoip_isnt_configured(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    honeypot_id = await _make_honeypot(db_session_factory, company.id)

    fake_result = LogPollResult(
        events=[
            {
                "logtype": 4002,
                "local_time": "2026-01-01 12:00:02.000000",
                "src_host": "203.0.113.7",
            },
        ],
        new_offset=1,
    )
    async def fake_poll_log(
        honeypot: object, secret: object, timeout_seconds: int, *, path: str = ""
    ):
        return fake_result

    monkeypatch.setattr("app.tasks.jobs.poll_log", fake_poll_log)

    async def fake_get_reader(db):
        return None

    monkeypatch.setattr("app.tasks.jobs.get_geoip_reader", fake_get_reader)

    await _poll_honeypot_canary_log(str(honeypot_id))

    async with db_session_factory() as db:
        event = (await db.execute(select(HoneypotEvent))).scalars().one()
        assert event.src_country_code is None
        assert event.src_latitude is None
