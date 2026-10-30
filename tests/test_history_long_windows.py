"""A window holding more rows than fit at once is thinned evenly (charts)
or counted in the database (event activity), never cut short: a 30/90-day
view used to show only its oldest ~28 days (oldest-first LIMIT), and a
flooded Activity/Dashboard chart read zero for its newest buckets."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.user import User
from app.services import monitoring_history
from app.services.canary_activity_history import (
    BUCKET_COUNT,
    build_activity_history,
    load_activity_history,
)
from app.web.routes.honeypots_common import _build_monitoring_context
from app.web.time_window import window_from_query

ROWS = 95
CAP = 10


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(monitoring_history, "MAX_RAW_SAMPLES", CAP)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def _seed_honeypot(db_session_factory: Any, now: datetime) -> uuid.UUID:
    async with db_session_factory() as session:
        honeypot = Honeypot(name="pi-1")
        session.add(honeypot)
        await session.flush()
        for i in range(ROWS):
            # one row per day, the newest an hour ago
            at = now - timedelta(days=ROWS - 1 - i, hours=1)
            session.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id,
                    sampled_at=at,
                    cpu_percent=float(i),
                    network_io=[{"iface": "eth0", "rx_bytes": i * 86400, "tx_bytes": 0}],
                )
            )
            session.add(
                HoneypotReachabilitySample(
                    honeypot_id=honeypot.id,
                    checked_at=at,
                    reachable=i != ROWS - 1,
                    latency_ms=float(i),
                )
            )
        await session.commit()
        return honeypot.id


async def _monitoring(db_session_factory: Any, honeypot_id: uuid.UUID, range_key: str) -> Any:
    async with db_session_factory() as session:
        honeypot = await session.get(Honeypot, honeypot_id)
        assert honeypot is not None
        user = User(username="root", is_superadmin=True)
        return await _build_monitoring_context(
            honeypot, window_from_query(range_key), session, user
        )


async def test_monitoring_spans_the_whole_window(db_session_factory: Any) -> None:
    now = datetime.now(UTC)
    honeypot_id = await _seed_honeypot(db_session_factory, now)
    context = await _monitoring(db_session_factory, honeypot_id, "90d")
    history, availability = context["history"], context["availability"]

    # 90 days back from now: rows 5..94 (days 89..0 ago) are inside.
    assert history.sample_count == 90
    assert availability.sample_count == 90
    assert history.truncated is False and availability.truncated is False
    stamps = [_as_utc(ts) for ts in history.bucket_timestamps]
    assert len(stamps) <= CAP + 1
    assert now - stamps[0] > timedelta(days=85)
    # the newest sample is always kept, so the latest reading is current
    assert now - stamps[-1] < timedelta(hours=2)
    assert availability.latest_reachable is False
    assert availability.latest_latency_ms == float(ROWS - 1)
    # rates from thinned cumulative counters are still per second
    rates = [v for v in history.network_rx_by_iface["eth0"] if v is not None]
    assert rates and all(v == pytest.approx(1.0) for v in rates)


async def test_short_window_returns_every_row(db_session_factory: Any) -> None:
    now = datetime.now(UTC)
    honeypot_id = await _seed_honeypot(db_session_factory, now)
    context = await _monitoring(db_session_factory, honeypot_id, "7d")
    assert context["history"].sample_count == context["availability"].sample_count == 7
    assert len(context["history"].bucket_timestamps) == 7


async def test_activity_counts_every_event_in_the_database(db_session_factory: Any) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    async with db_session_factory() as session:
        honeypot = Honeypot(name="pi-2")
        session.add(honeypot)
        await session.flush()
        events = []
        for i in range(120):
            # a steady trickle over the day, then a flood in the last hour
            minutes_ago = 12 * (i + 1) if i < 100 else i - 99
            at = now - timedelta(minutes=minutes_ago)
            event = HoneypotEvent(
                honeypot_id=honeypot.id,
                event_type="4002" if i % 3 else "3000",
                occurred_at=at,
                raw={},
                source="ssh_poll",
            )
            events.append(event)
            session.add(event)
        # outside the window, never counted
        session.add(
            HoneypotEvent(
                honeypot_id=honeypot.id,
                event_type="4002",
                occurred_at=now - timedelta(days=3),
                raw={},
                source="ssh_poll",
            )
        )
        await session.commit()
        honeypot_id = honeypot.id

    async with db_session_factory() as session:
        counted = await load_activity_history(
            session,
            [
                HoneypotEvent.honeypot_id == honeypot_id,
                HoneypotEvent.occurred_at >= now - timedelta(days=1),
                HoneypotEvent.occurred_at <= now,
            ],
            "24h",
            now=now,
        )

    in_window = [e for e in events if e.occurred_at >= now - timedelta(days=1)]
    expected = build_activity_history(in_window, "24h", now=now)
    assert counted.total == len(in_window) == counted.sample_count
    assert counted.total_counts == expected.total_counts
    assert counted.totals_by_type == expected.totals_by_type
    assert counted.counts_by_type == expected.counts_by_type
    assert len(counted.total_counts) == BUCKET_COUNT
    # the flood lands in the newest bucket
    assert counted.total_counts[-1] >= 20
