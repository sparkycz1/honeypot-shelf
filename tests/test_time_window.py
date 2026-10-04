"""A chart page's time window: one of the presets, or a custom from-to
stretch (`app.services.monitoring_history.TimeWindow`,
`app.web.time_window`) — on the Monitoring and Activity tabs."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.services import monitoring_history
from app.services.canary_activity_history import BUCKET_COUNT, build_activity_history
from app.web.time_window import window_from_query, window_query
from tests.conftest import create_company

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def test_a_preset_ends_now_and_an_unknown_key_falls_back() -> None:
    window = monitoring_history.resolve_window("7d", now=NOW)
    assert (window.range_key, window.since, window.until) == ("7d", NOW - timedelta(days=7), None)
    assert not window.is_custom and window.axis_format == "%d.%m."
    fallback = monitoring_history.resolve_window("nonsense", now=NOW)
    assert fallback.range_key == monitoring_history.DEFAULT_TIME_RANGE


def test_a_custom_window_is_ordered_and_clamped() -> None:
    start, end = NOW - timedelta(hours=6), NOW - timedelta(hours=2)
    window = monitoring_history.resolve_window("7d", start, end, now=NOW)
    assert window.is_custom and (window.since, window.until) == (start, end)

    swapped = monitoring_history.resolve_window("1h", end, start, now=NOW)
    assert (swapped.since, swapped.until) == (start, end)
    future = monitoring_history.resolve_window("1h", start, NOW + timedelta(days=1), now=NOW)
    assert future.until == NOW
    assert not monitoring_history.resolve_window("24h", start, None, now=NOW).is_custom


def test_the_query_string_round_trips() -> None:
    assert window_query(window_from_query("24h")) == "range_key=24h"
    assert not window_from_query("24h", "garbage", "2026-10-01T10:00").is_custom
    custom = window_from_query("", "2026-10-01T08:00:00+00:00", "2026-10-01T10:00:00Z")
    query = parse_qs(window_query(custom))
    again = window_from_query("", query["start"][0], query["end"][0])
    assert (again.since, again.until) == (custom.since, custom.until)


def test_activity_buckets_follow_a_custom_window() -> None:
    start = NOW - timedelta(hours=4)
    events = [
        HoneypotEvent(event_type="4002", occurred_at=start + timedelta(minutes=1), raw={}),
        HoneypotEvent(event_type="4002", occurred_at=NOW - timedelta(minutes=1), raw={}),
    ]
    history = build_activity_history(events, "custom", now=NOW, start=start)
    assert history.total_counts[0] == 1 and history.total_counts[BUCKET_COUNT - 1] == 1
    assert history.bucket_timestamps[0] > start and history.bucket_timestamps[-1] < NOW


async def _honeypot_with_history(db_session_factory: Any) -> tuple[Any, datetime]:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="acme-honey1")
        db.add(honeypot)
        await db.flush()
        base = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=10)
        for hour in range(10):
            at = base + timedelta(hours=hour)
            db.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id, sampled_at=at, cpu_percent=float(hour)
                )
            )
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id, event_type="4002", occurred_at=at, raw={}
                )
            )
        honeypot.monitoring_updated_at = base + timedelta(hours=9)
        honeypot.opencanary_log_polled_at = base + timedelta(hours=9)
        await db.commit()
        return honeypot.id, base


def _charts(html: str) -> list[dict[str, Any]]:
    return [
        json.loads(raw.replace("&#34;", '"')) for raw in re.findall(r"data-chart='([^']+)'", html)
    ]


async def test_monitoring_tab_shows_only_the_custom_window(
    client: Any, db_session_factory: Any
) -> None:
    honeypot_id, base = await _honeypot_with_history(db_session_factory)
    params = {
        "start": (base + timedelta(hours=2)).isoformat(),
        "end": (base + timedelta(hours=5)).isoformat(),
    }

    page = await client.get(f"/honeypots/{honeypot_id}/monitoring", params=params)
    assert page.status_code == 200
    assert 'name="start"' in page.text and "data-chart-zoom" in page.text
    cpu = next(c for c in _charts(page.text) if c["s"] and c["s"][0]["v"] == [2.0, 3.0, 4.0, 5.0])
    assert cpu["e"] == [int((base + timedelta(hours=h)).timestamp()) for h in (2, 3, 4, 5)]
    # The self-refreshing panel and "Refresh now" stay on the same window.
    assert "monitoring-panel?start=" in page.text
    assert '&#34;start&#34;: &#34;20' in page.text or '"start": "20' in page.text

    panel = await client.get(f"/honeypots/{honeypot_id}/monitoring-panel", params=params)
    assert panel.status_code == 200 and 'name="end"' in panel.text

    preset = await client.get(f"/honeypots/{honeypot_id}/monitoring", params={"range_key": "24h"})
    assert "monitoring-panel?range_key=24h" in preset.text


async def test_activity_tab_and_export_follow_the_custom_window(
    client: Any, db_session_factory: Any
) -> None:
    honeypot_id, base = await _honeypot_with_history(db_session_factory)
    params = {
        "start": (base + timedelta(hours=2)).isoformat(),
        "end": (base + timedelta(hours=5)).isoformat(),
    }

    page = await client.get(f"/honeypots/{honeypot_id}/status", params=params)
    assert page.status_code == 200
    assert "activity-panel?start=" in page.text
    total = next(c for c in _charts(page.text) if len(c["s"]) == 1)
    assert sum(total["s"][0]["v"]) == 4

    export = await client.get(
        f"/honeypots/{honeypot_id}/status/export", params={**params, "format": "json"}
    )
    assert export.status_code == 200
    assert len(export.json()) == 4
    everything = await client.get(
        f"/honeypots/{honeypot_id}/status/export", params={"format": "json"}
    )
    assert len(everything.json()) == 10
