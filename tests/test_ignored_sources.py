"""The ignore list for event sources (`app.services.ignored_sources`): what
an entry may be, what an ignored event stays out of, and the page and API
that manage the list."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.ignored_source import IgnoredSource
from app.db.models.user import User
from app.services import ignored_sources
from app.tasks import jobs
from tests.conftest import create_company


def test_an_entry_is_an_address_or_a_reasonably_small_network() -> None:
    assert ignored_sources.parse_network(" 203.0.113.7 ") == "203.0.113.7/32"
    assert ignored_sources.parse_network("203.0.113.9/24") == "203.0.113.0/24"
    assert ignored_sources.parse_network("2001:db8::1") == "2001:db8::1/128"
    for bad in ("", "not-an-ip", "0.0.0.0/0", "10.0.0.0/4", "2001:db8::/16"):
        with pytest.raises(ValueError):
            ignored_sources.parse_network(bad)


def test_matching_is_by_network_and_tolerates_bad_input() -> None:
    networks = [ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32")]
    assert ignored_sources.matches("203.0.113.200", networks)
    assert ignored_sources.matches("2001:db8::5", networks)
    assert not ignored_sources.matches("198.51.100.1", networks)
    assert not ignored_sources.matches(None, networks)
    assert not ignored_sources.matches("garbage", networks)


async def _seed(db_session_factory: Any) -> tuple[Any, Any, Any]:
    """Two companies with one honeypot each; the scanner hits both, an
    attacker hits the first. Returns the company ids and the first
    honeypot's id."""
    atlas = await create_company(db_session_factory, name="Atlas")
    borealis = await create_company(db_session_factory, name="Borealis")
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        first = Honeypot(companies=[await db.get(Company, atlas.id)], name="atlas-honey")
        second = Honeypot(companies=[await db.get(Company, borealis.id)], name="borealis-honey")
        db.add_all([first, second])
        await db.flush()
        hits = (
            (first, "10.9.9.9"),
            (first, "10.9.9.9"),
            (first, "203.0.113.7"),
            (second, "10.9.9.9"),
        )
        for honeypot, ip in hits:
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type="4002",
                    occurred_at=now - timedelta(minutes=5),
                    src_ip=ip,
                    raw={},
                )
            )
        await db.commit()
        return atlas.id, borealis.id, first.id


async def _ignored_count(db_session_factory: Any) -> int:
    async with db_session_factory() as db:
        rows = (await db.execute(select(HoneypotEvent.ignored))).scalars().all()
    return sum(1 for ignored in rows if ignored)


@pytest.fixture
def _worker_session(db_session_factory: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)


async def test_a_company_entry_quiets_only_that_companys_honeypots(
    db_session_factory: Any, _worker_session: None
) -> None:
    atlas_id, _borealis, _first = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add(IgnoredSource(company_id=atlas_id, network="10.9.9.0/24"))
        await db.commit()

    result = await jobs._reapply_ignored_sources()
    assert result["changed"] == 2
    assert await _ignored_count(db_session_factory) == 2

    # Removing the entry brings the events back.
    async with db_session_factory() as db:
        entry = (await db.execute(select(IgnoredSource))).scalar_one()
        await db.delete(entry)
        await db.commit()
    assert (await jobs._reapply_ignored_sources())["changed"] == 2
    assert await _ignored_count(db_session_factory) == 0


async def test_ignored_events_stay_out_of_the_pages(
    client: Any, db_session_factory: Any, _worker_session: None
) -> None:
    _atlas, _borealis, first_id = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add(IgnoredSource(company_id=None, network="10.9.9.9/32", note="our scanner"))
        await db.commit()
    await jobs._reapply_ignored_sources()

    listing = await client.get("/events")
    assert listing.text.count('<td class="cell-nowrap">') == 1
    with_ignored = await client.get("/events", params={"include_ignored": "1"})
    assert with_ignored.text.count('<td class="cell-nowrap">') == 4

    activity = await client.get(f"/honeypots/{first_id}/status")
    assert "203.0.113.7" in activity.text and "10.9.9.9" not in activity.text
    dashboard = await client.get("/dashboard")
    assert "10.9.9.9" not in dashboard.text

    source = await client.get("/events/source/10.9.9.9")
    assert source.status_code == 200 and "ignore list" in source.text


async def test_page_adds_validates_and_removes(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    atlas_id, _borealis, _first = await _seed(db_session_factory)
    page = await client.get("/events/ignored", params={"network": "10.9.9.9"})
    assert 'value="10.9.9.9"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    too_wide = await client.post("/events/ignored", data={**csrf, "network": "0.0.0.0/0"})
    assert too_wide.status_code == 422 and "too wide" in too_wide.text
    added = await client.post(
        "/events/ignored",
        data={**csrf, "network": "10.9.9.9", "company_id": str(atlas_id), "note": "scanner"},
        follow_redirects=False,
    )
    assert added.status_code == 303
    again = await client.post(
        "/events/ignored", data={**csrf, "network": "10.9.9.9", "company_id": str(atlas_id)}
    )
    assert again.status_code == 422

    async with db_session_factory() as db:
        entry = (await db.execute(select(IgnoredSource))).scalar_one()
        assert (entry.network, entry.note, entry.company_id) == ("10.9.9.9/32", "scanner", atlas_id)
    assert "scanner" in (await client.get("/events/ignored")).text

    removed = await client.post(
        f"/events/ignored/{entry.id}/delete", data=csrf, follow_redirects=False
    )
    assert removed.status_code == 303
    async with db_session_factory() as db:
        assert (await db.execute(select(IgnoredSource))).scalars().all() == []
    queued = [name for name, _args, _kwargs in celery_calls]
    assert queued.count("app.tasks.jobs.reapply_ignored_sources") == 2


async def test_only_those_with_write_access_manage_the_list(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, borealis_id, _first = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add_all(
            [
                IgnoredSource(company_id=None, network="192.0.2.1/32"),
                IgnoredSource(company_id=borealis_id, network="192.0.2.2/32"),
            ]
        )
        await db.commit()
        everywhere = (
            await db.execute(select(IgnoredSource).where(IgnoredSource.company_id.is_(None)))
        ).scalar_one()
    await login_as(
        client, username="writer", company_id=atlas_id, access_level=AccessLevel.READ_WRITE
    )
    page = await client.get("/events/ignored")
    # Sees the entry for every honeypot, not another company's.
    assert "192.0.2.1/32" in page.text and "192.0.2.2/32" not in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    not_allowed = (
        {"network": "198.51.100.1"},
        {"network": "198.51.100.1", "company_id": str(borealis_id)},
    )
    for data in not_allowed:
        refused = await client.post("/events/ignored", data={**csrf, **data})
        assert refused.status_code == 403
    cannot_remove = await client.post(f"/events/ignored/{everywhere.id}/delete", data=csrf)
    assert cannot_remove.status_code == 403
    own = await client.post(
        "/events/ignored",
        data={**csrf, "network": "198.51.100.1", "company_id": str(atlas_id)},
        follow_redirects=False,
    )
    assert own.status_code == 303


async def test_api_manages_the_list(client: Any, login_as: Any, db_session_factory: Any) -> None:
    atlas_id, _borealis, _first = await _seed(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw_token}"}

    bad = await client.post("/api/v1/events/ignored", json={"network": "nope"}, headers=headers)
    assert bad.status_code == 422
    created = await client.post(
        "/api/v1/events/ignored",
        json={"network": "10.9.9.0/24", "company_id": str(atlas_id), "note": "scanner"},
        headers=headers,
    )
    assert created.status_code == 201 and created.json()["network"] == "10.9.9.0/24"
    duplicate = await client.post(
        "/api/v1/events/ignored",
        json={"network": "10.9.9.0/24", "company_id": str(atlas_id)},
        headers=headers,
    )
    assert duplicate.status_code == 409

    listed = (await client.get("/api/v1/events/ignored", headers=headers)).json()["ignored"]
    assert [entry["network"] for entry in listed] == ["10.9.9.0/24"]
    removed = await client.delete(
        f"/api/v1/events/ignored/{created.json()['id']}", headers=headers
    )
    assert removed.status_code == 204
