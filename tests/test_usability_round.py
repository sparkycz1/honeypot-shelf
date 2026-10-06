"""A round of usability fixes: a summary on a honeypot's overview, a
History tab without the noise, repeated events folded together, a Map
that says something on an internal-only installation, a bulk bar that
appears when it is needed, and pages that don't ripple while idle."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.audit import log_event
from app.db.models.company import Company
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.services.event_search import group_repeats
from app.services.geoip_display import is_internal_address
from app.services.honeypot_timeline import TimelineEvent, _merge_terminal_sessions
from app.web.templating import short_duration
from tests.conftest import create_company

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = _ROOT / "app" / "web" / "templates"
_STATIC = _ROOT / "app" / "web" / "static"


async def _honeypot(db_session_factory: Any, **fields: Any) -> uuid.UUID:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="hp-usable",
            ip_address="10.8.8.8",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            is_reachable=True,
            **fields,
        )
        db.add(honeypot)
        await db.commit()
        return honeypot.id


async def _events(
    db_session_factory: Any, honeypot_id: uuid.UUID, rows: list[tuple[str, str, int]]
) -> None:
    """`rows`: (source address, event type, seconds ago)."""
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        for src_ip, event_type, seconds_ago in rows:
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot_id,
                    event_type=event_type,
                    occurred_at=now - timedelta(seconds=seconds_ago),
                    src_ip=src_ip,
                    raw={},
                )
            )
        await db.commit()


# --- Overview summary ----------------------------------------------------


@pytest.mark.asyncio
async def test_overview_opens_with_a_summary(client: Any, db_session_factory: Any) -> None:
    honeypot_id = await _honeypot(
        db_session_factory,
        last_seen_at=datetime.now(UTC),
        opencanary_log_polled_at=datetime.now(UTC),
        updates_checked_at=datetime.now(UTC),
        upgradable_count=3,
        reboot_required=True,
    )
    await _events(
        db_session_factory, honeypot_id, [("10.1.1.1", "4002", 30), ("10.1.1.2", "4002", 90)]
    )

    page = (await client.get(f"/honeypots/{honeypot_id}")).text
    summary = page.split('<div class="summary-row">', 1)[1].split('<dl class="detail-list">', 1)[0]
    for label in ("Status", "Last event", "Events in 24 h", "Updates", "Last check"):
        assert f'<span class="summary-label">{label}</span>' in summary
    assert "SSH reachable" in summary and "OpenCanary reporting" in summary
    assert f'<a href="/honeypots/{honeypot_id}/status">2</a>' in summary
    assert "reboot" in summary
    # The summary comes before the address and the key fingerprint.
    assert page.index('class="summary-row"') < page.index("10.8.8.8")


# --- History -------------------------------------------------------------


def _audit(action: str, at: datetime, **data: Any) -> TimelineEvent:
    return TimelineEvent(
        at=at, kind="audit", summary=action, actor="jana", data={"action": action, **data}
    )


def test_terminal_open_and_close_become_one_session() -> None:
    start = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)
    merged = _merge_terminal_sessions(
        [
            _audit("honeypot.terminal.open", start + timedelta(hours=2)),  # still running
            _audit(
                "honeypot.terminal.close", start + timedelta(minutes=12), duration_seconds=720.0
            ),
            _audit("honeypot.update", start + timedelta(minutes=5)),
            _audit("honeypot.terminal.open", start + timedelta(seconds=1)),
        ]
    )
    assert [e.data["action"] for e in merged] == [
        "honeypot.terminal.open",
        "honeypot.update",
        "honeypot.terminal.session",
    ]
    session = merged[-1]
    assert session.at == start and session.data["duration_seconds"] == 720.0


@pytest.mark.asyncio
async def test_history_leaves_out_manual_refreshes(client: Any, db_session_factory: Any) -> None:
    honeypot_id = await _honeypot(db_session_factory)
    async with db_session_factory() as db:
        for action, summary in (
            ("honeypot.activity.refresh", "Refreshed activity"),
            ("honeypot.monitoring.refresh", "Refreshed monitoring"),
            ("honeypot.update", "Edited the honeypot"),
        ):
            await log_event(
                db,
                action=action,
                summary=summary,
                actor="jana",
                target_type="honeypot",
                target_id=honeypot_id,
            )
        await log_event(
            db,
            action="honeypot.terminal.close",
            summary="Closed terminal after 125s",
            actor="jana",
            target_type="honeypot",
            target_id=honeypot_id,
            details={"duration_seconds": 125.0},
        )
    page = (await client.get(f"/honeypots/{honeypot_id}/history")).text
    assert "Edited the honeypot" in page
    assert "Refreshed activity" not in page and "Refreshed monitoring" not in page
    assert "Terminal session, 2 min" in page


def test_short_duration_reads_like_a_person_would_say_it() -> None:
    assert short_duration(45) == "45 s"
    assert short_duration(125) == "2 min"
    assert short_duration(3900) == "1 h 05 min"
    assert short_duration(None) == "0 s"


# --- Events --------------------------------------------------------------


def _event(src_ip: str, event_type: str, seconds_ago: int, honeypot_id: uuid.UUID) -> HoneypotEvent:
    return HoneypotEvent(
        honeypot_id=honeypot_id,
        event_type=event_type,
        occurred_at=datetime(2026, 10, 6, 12, 0, tzinfo=UTC) - timedelta(seconds=seconds_ago),
        src_ip=src_ip,
        ignored=False,
        raw={},
    )


def test_identical_events_in_a_row_fold_into_one_row() -> None:
    hp = uuid.uuid4()
    rows = group_repeats(
        [
            _event("10.0.0.5", "13001", 0, hp),
            _event("10.0.0.5", "13001", 0, hp),
            _event("10.0.0.5", "13001", 1, hp),
            _event("10.0.0.6", "13001", 2, hp),  # another source
            _event("10.0.0.5", "13001", 3, hp),  # same again, but not adjacent
            _event("10.0.0.5", "13001", 600, hp),  # same, ten minutes earlier
        ]
    )
    assert [row.count for row in rows] == [3, 1, 1, 1]
    assert rows[0].event.occurred_at == datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_events_page_shows_the_total_and_folds_repeats(
    client: Any, db_session_factory: Any
) -> None:
    honeypot_id = await _honeypot(db_session_factory)
    await _events(
        db_session_factory,
        honeypot_id,
        [("10.0.0.5", "13001", 10), ("10.0.0.5", "13001", 10), ("203.0.113.9", "4002", 500)],
    )
    page = (await client.get("/events")).text
    assert "3 events found" in page
    assert page.count('<td class="cell-nowrap">') == 2
    assert ">2\u00d7</span>" in page
    # A private address has no country — say what it is instead of nothing.
    assert "internal network" in page

    one = (await client.get("/events", params={"src_ip": "203.0.113.9"})).text
    assert "1 event found" in one

    activity = (await client.get(f"/honeypots/{honeypot_id}/status")).text
    assert ">2\u00d7</span>" in activity


def test_internal_addresses_are_recognised() -> None:
    for address in (
        "10.1.2.3",
        "192.168.0.10",
        "172.16.5.5",
        "127.0.0.1",
        "fd00::1",
        "169.254.1.1",
    ):
        assert is_internal_address(address), address
    outside: tuple[str | None, ...] = (
        "8.8.8.8",
        "198.51.100.4",  # reserved for documentation, nobody's LAN
        "2001:4860:4860::8888",
        "",
        None,
        "not-an-address",
    )
    for other in outside:
        assert not is_internal_address(other), other


@pytest.mark.asyncio
async def test_internal_source_says_internal_network_as_its_location(
    client: Any, db_session_factory: Any
) -> None:
    honeypot_id = await _honeypot(db_session_factory)
    await _events(db_session_factory, honeypot_id, [("10.0.0.5", "13001", 10)])
    source = (await client.get("/events/source/10.0.0.5")).text
    location = source.split("Location", 1)[1].split("</dd>", 1)[0]
    assert "internal network" in location


# --- Map -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_map_lists_the_busiest_internal_sources(client: Any, db_session_factory: Any) -> None:
    honeypot_id = await _honeypot(db_session_factory)
    await _events(
        db_session_factory,
        honeypot_id,
        [("10.0.0.5", "13001", 10), ("10.0.0.5", "13001", 300), ("10.0.0.6", "13001", 20)]
        # A public address the GeoIP database doesn't know is not "internal".
        + [("198.51.100.4", "4002", 30)] * 3,
    )
    page = (await client.get("/map")).text
    section = page.split("Most frequent internal sources", 1)[1]
    assert section.index("10.0.0.5") < section.index("10.0.0.6")
    assert 'href="/events/source/10.0.0.5"' in section
    assert "198.51.100.4" not in section


# --- Honeypot list -------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_bar_waits_for_a_selection_and_sets_danger_apart(
    client: Any, db_session_factory: Any
) -> None:
    await _honeypot(db_session_factory)
    page = (await client.get("/honeypots")).text
    assert 'data-bulk-bar="honeypot_ids" hidden' in page
    assert 'data-bulk-empty="honeypot_ids"' in page
    assert 'data-bulk-count data-label="Selected:"' in page
    danger = page.split("bulk-bar-danger", 1)[1].split("</div>", 1)[0]
    for action in ("power-confirm/reboot", "power-confirm/shutdown", "bulk/delete"):
        assert action in danger
    assert "bulk/check-updates" not in danger

    script = (_STATIC / "js" / "bulk-select.js").read_text(encoding="utf-8")
    assert "bar.hidden = selected === 0" in script


@pytest.mark.asyncio
async def test_honeypot_table_cells_carry_their_column_name_for_the_card_layout(
    client: Any, db_session_factory: Any
) -> None:
    await _honeypot(db_session_factory)
    page = (await client.get("/honeypots")).text
    assert '<table class="data-table honeypot-table">' in page
    for label in ("Name", "Tags", "Company", "Status"):
        assert f'<td data-label="{label}">' in page, label
    css = (_STATIC / "css" / "style.css").read_text(encoding="utf-8")
    assert ".honeypot-table td[data-label]::before" in css


# --- Tabs, empty pages, quiet refreshes ----------------------------------


def test_managing_tabs_are_set_apart_from_watching_ones() -> None:
    css = (_STATIC / "css" / "style.css").read_text(encoding="utf-8")
    assert '.tab-nav a[href^="/honeypots/"][href$="/updates"]::before' in css


@pytest.mark.asyncio
async def test_empty_scheduling_page_says_what_it_is_for(client: Any) -> None:
    page = (await client.get("/scheduling")).text
    empty = page.split('class="empty-state"', 1)[1].split("</div>", 1)[0]
    assert "recurring action" in empty
    assert 'href="/scheduling/new"' in empty


@pytest.mark.asyncio
async def test_empty_notifications_page_opens_the_form(client: Any) -> None:
    page = (await client.get("/account/notifications")).text
    assert 'class="empty-state stack-gap"' in page
    assert '<details class="stack-gap" open>' in page


def test_whole_page_panels_refresh_quietly() -> None:
    for relative in (
        "dashboard/index.html",
        "map/index.html",
        "audit/list.html",
        "companies/list.html",
    ):
        text = (_TEMPLATES / relative).read_text(encoding="utf-8")
        assert "data-quiet-swap" in text, relative
        assert "settle:600ms" not in text, relative
    assert "js/quiet-swap.js" in (_TEMPLATES / "base.html").read_text(encoding="utf-8")
    css = (_STATIC / "css" / "style.css").read_text(encoding="utf-8")
    assert "scrollbar-gutter: stable" in css
    assert "[data-quiet-swap].htmx-settling { animation: none; }" in css
