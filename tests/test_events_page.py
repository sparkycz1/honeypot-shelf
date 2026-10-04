"""The Events page (`/events`): events across honeypots with filters and
an export, inside the account's companies — and the same filters in the
REST API (`app.services.event_search`)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.auth.api_tokens import create_api_token
from app.db.models.access_level import AccessLevel
from app.db.models.audit_log import AuditLogEntry
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.user import User
from tests.conftest import create_company

BASE = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


async def _seed(db_session_factory: Any) -> tuple[Any, Any, Any]:
    """Two companies, a honeypot each, three events on the first and one
    on the second; returns the company ids and the first honeypot's id."""
    atlas = await create_company(db_session_factory, name="Atlas")
    borealis = await create_company(db_session_factory, name="Borealis")
    async with db_session_factory() as db:
        first = Honeypot(companies=[await db.get(Company, atlas.id)], name="atlas-honey")
        second = Honeypot(companies=[await db.get(Company, borealis.id)], name="borealis-honey")
        db.add_all([first, second])
        await db.flush()
        rows = [
            (first, "4002", "203.0.113.7", "CZ", 0),
            (first, "4002", "203.0.113.9", "DE", 1),
            (first, "3000", "198.51.100.4", "CZ", 2),
            (second, "4002", "203.0.113.7", "CZ", 3),
        ]
        for honeypot, event_type, ip, country, hour in rows:
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type=event_type,
                    occurred_at=BASE + timedelta(hours=hour),
                    src_ip=ip,
                    src_country_code=country,
                    raw={},
                )
            )
        await db.commit()
        return atlas.id, borealis.id, first.id


def _rows(html: str) -> int:
    return html.count('<td class="cell-nowrap">')


async def test_events_page_lists_and_filters(client: Any, db_session_factory: Any) -> None:
    _atlas, _borealis, first_id = await _seed(db_session_factory)

    page = await client.get("/events")
    assert page.status_code == 200 and _rows(page.text) == 4
    assert "atlas-honey" in page.text and "borealis-honey" in page.text
    # Newest first.
    assert page.text.index("borealis-honey</a>") < page.text.index("atlas-honey</a>")

    for params, expected in [
        ({"src_ip": "203.0.113."}, 3),
        ({"src_ip": "203.0.113.7"}, 2),
        ({"event_type": "3000"}, 1),
        ({"country": "de"}, 1),
        ({"honeypot_id": str(first_id)}, 3),
        ({"honeypot_id": "not-a-uuid"}, 4),
        ({"since": (BASE + timedelta(hours=2)).isoformat()}, 2),
        ({"until": (BASE + timedelta(minutes=30)).isoformat()}, 1),
        ({"src_ip": "203.0.113.7", "event_type": "3000"}, 0),
        ({"src_ip": "%"}, 0),
    ]:
        response = await client.get("/events", params=params)
        assert response.status_code == 200
        assert _rows(response.text) == expected, params


async def test_events_page_stays_inside_the_accounts_companies(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    atlas_id, _borealis, _first = await _seed(db_session_factory)
    await login_as(client, username="reader", company_id=atlas_id, access_level=AccessLevel.READ)

    page = await client.get("/events")
    assert _rows(page.text) == 3
    assert "borealis-honey" not in page.text
    export = await client.get("/events/export", params={"format": "json"})
    assert len(export.json()) == 3


async def test_export_follows_the_filters_and_is_audited(
    client: Any, db_session_factory: Any
) -> None:
    await _seed(db_session_factory)

    as_json = await client.get("/events/export", params={"format": "json", "country": "CZ"})
    assert as_json.status_code == 200 and len(as_json.json()) == 3
    as_csv = await client.get("/events/export", params={"src_ip": "198.51.100.4"})
    assert as_csv.headers["content-type"].startswith("text/csv")
    assert as_csv.text.count("198.51.100.4") == 1

    async with db_session_factory() as db:
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert actions.count("event.export") == 2


async def test_every_page_links_to_events(client: Any) -> None:
    assert 'href="/events"' in (await client.get("/dashboard")).text


async def test_api_takes_the_same_filters(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _seed(db_session_factory)
    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    headers = {"Authorization": f"Bearer {raw_token}"}

    by_ip = await client.get("/api/v1/events", params={"src_ip": "203.0.113."}, headers=headers)
    assert len(by_ip.json()["events"]) == 3
    by_country = await client.get("/api/v1/events", params={"country": "DE"}, headers=headers)
    assert [e["src_ip"] for e in by_country.json()["events"]] == ["203.0.113.9"]
    export = await client.get(
        "/api/v1/events/export", params={"format": "json", "country": "CZ"}, headers=headers
    )
    assert len(export.json()) == 3
