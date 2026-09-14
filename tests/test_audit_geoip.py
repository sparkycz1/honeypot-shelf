"""`app.audit.log_event`'s GeoIP enrichment — a written entry's
`source_country_code`/`source_country_name`/`source_city_name` come from
`app.services.geoip.resolve`, best-effort, and are never part of the hash
chain (`entry_hash`) itself — see `app.db.models.audit_log.AuditLogEntry`'s
own comment on why. Monkeypatches `resolve_geoip` directly rather than a
real MaxMind database, same reasoning as `tests/test_geoip.py`."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.audit import _canonical_payload, _compute_entry_hash, log_event, verify_chain
from app.db.models.audit_log import AuditLogEntry
from app.services.geoip import GeoLocation

pytestmark = pytest.mark.asyncio


async def test_log_event_stores_the_resolved_country(db_session_factory, monkeypatch):
    async def fake_resolve(db, ip_str):
        assert ip_str == "203.0.113.7"
        return GeoLocation(
            country_code="US",
            country_name="United States",
            city_name="Mountain View",
            latitude=37.4,
            longitude=-122.1,
        )

    monkeypatch.setattr("app.audit.resolve_geoip", fake_resolve)

    async with db_session_factory() as db:
        await log_event(
            db,
            action="test.action",
            summary="A test entry",
            ip_address="203.0.113.7",
            actor="tester",
        )
        entry = (await db.execute(select(AuditLogEntry))).scalars().one()
        assert entry.source_country_code == "US"
        assert entry.source_country_name == "United States"
        assert entry.source_city_name == "Mountain View"


async def test_log_event_leaves_country_fields_none_when_geoip_unconfigured(db_session_factory):
    """The default state in every other test in this suite - no
    GeoipDatabase row exists at all - must never crash or block a write."""
    async with db_session_factory() as db:
        await log_event(
            db,
            action="test.action",
            summary="A test entry",
            ip_address="203.0.113.7",
            actor="tester",
        )
        entry = (await db.execute(select(AuditLogEntry))).scalars().one()
        assert entry.source_country_code is None


async def test_geo_fields_are_excluded_from_the_hash_chain(db_session_factory, monkeypatch):
    """Confirms the design decision directly: recomputing entry_hash from
    only the fields `_canonical_payload` actually takes (never geo data)
    must reproduce the exact hash the write stored - proving geo columns
    played no part in it, not just that verify_chain happens to still
    pass."""

    async def fake_resolve(db, ip_str):
        return GeoLocation(
            country_code="US",
            country_name="United States",
            city_name="Mountain View",
            latitude=37.4,
            longitude=-122.1,
        )

    monkeypatch.setattr("app.audit.resolve_geoip", fake_resolve)
    async with db_session_factory() as db:
        await log_event(
            db, action="test.action", summary="same", ip_address="203.0.113.7", actor="tester"
        )
        entry = (await db.execute(select(AuditLogEntry))).scalars().one()

    assert entry.source_country_code == "US"  # geo really was resolved

    payload = _canonical_payload(
        entry_id=entry.id,
        sequence=entry.sequence,
        created_at=entry.created_at,
        actor=entry.actor,
        ip_address=entry.ip_address,
        action=entry.action,
        outcome=entry.outcome,
        target_type=entry.target_type,
        target_id=entry.target_id,
        target_label=entry.target_label,
        summary=entry.summary,
        details=entry.details,
    )
    recomputed = _compute_entry_hash(entry.prev_hash, payload)
    assert recomputed == entry.entry_hash


async def test_verify_chain_still_passes_with_geo_fields_populated(db_session_factory, monkeypatch):
    async def fake_resolve(db, ip_str):
        return GeoLocation(
            country_code="US", country_name="United States", city_name=None,
            latitude=None, longitude=None,
        )

    monkeypatch.setattr("app.audit.resolve_geoip", fake_resolve)
    async with db_session_factory() as db:
        await log_event(db, action="a", summary="one", ip_address="203.0.113.7")
        await log_event(db, action="b", summary="two", ip_address="203.0.113.7")
        result = await verify_chain(db)
        assert result.ok
