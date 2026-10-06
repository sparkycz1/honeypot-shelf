from __future__ import annotations

import html
import json
import re
from datetime import UTC, datetime, timedelta

from app.web.charts import build_chart, format_value, nice_range

_TS = [datetime(2026, 9, 23, 19, 30, tzinfo=UTC) + timedelta(minutes=2 * i) for i in range(10)]


def test_format_value_per_format():
    assert format_value(3.456, "percent") == "3.46%"
    assert format_value(1536, "bytes") == "1.5 KB"
    assert format_value(12 * 1024, "bytes_rate") == "12 KB/s"
    assert format_value(44.0, "celsius") == "44 °C"
    assert format_value(3.2, "watts") == "3.2 W"
    assert format_value(1409.4, "rpm") == "1409"
    assert format_value(None, "percent") == "—"


def test_nice_range_rounds_to_friendly_ticks():
    assert nice_range(0, 3.3, "percent") == (0.0, 4.0, 1.0)
    lo, hi, step = nice_range(0, 900 * 1024**2, "bytes")
    assert (lo, hi, step) == (0.0, 1000 * 1024**2, 250 * 1024**2)


def test_percent_axis_autoscales_but_never_past_100():
    low = build_chart([("cpu", [1.0, 3.2] * 5)], _TS, fmt="percent")
    high = build_chart([("cpu", [90.0, 99.0] * 5)], _TS, fmt="percent")

    assert low.y_ticks[0] == "4%"
    assert high.y_ticks[0] == "100%"
    assert low.y_ticks[-1] == high.y_ticks[-1] == "0%"


def test_flat_series_without_zero_base_gets_a_readable_axis():
    chart = build_chart([("fan1", [1409.0] * 10)], _TS, fmt="rpm", zero_based=False)

    assert chart.y_ticks == ["1411", "1410", "1409", "1408", "1407"]


def test_gaps_split_a_series_into_separate_paths():
    values = [1.0, 2.0, None, None, 3.0, 4.0, 5.0, None, 1.0, 2.0]

    chart = build_chart([("x", values)], _TS, fmt="number")

    assert len(chart.series[0].line_paths) == 3
    assert chart.series[0].values[2] is None


def test_stacked_areas_sit_on_top_of_each_other():
    chart = build_chart([("a", [1.0] * 10), ("b", [2.0] * 10)], _TS, fmt="number", stacked=True)

    # The axis covers the stacked total (3), not the largest single series (2).
    assert chart.y_ticks[0] == "3"
    assert chart.stacked and chart.area
    assert len(chart.series[1].area_paths) == 1
    assert chart.series[1].area_paths[0].endswith("Z")
    # Tooltip data keeps each series' own value, not the running total.
    assert chart.data["s"][1]["v"][0] == 2.0


def test_many_series_are_lines_not_areas_by_default():
    chart = build_chart([(f"s{i}", [float(i)] * 10) for i in range(5)], _TS, fmt="celsius")

    assert not chart.area
    assert all(not s.area_paths for s in chart.series)


def test_threshold_outside_the_axis_is_dropped():
    inside = build_chart([("cpu", [10.0] * 10)], _TS, fmt="percent", fixed_max=100, threshold=90)
    outside = build_chart([("cpu", [10.0] * 10)], _TS, fmt="percent", fixed_max=100, threshold=150)

    assert inside.threshold_y is not None
    assert outside.threshold_y is None


def test_x_ticks_are_evenly_spread_time_labels():
    chart = build_chart(
        [("x", [1.0] * 10)], _TS, fmt="number", time_label=lambda dt, f: dt.strftime(f)
    )

    assert chart.x_ticks[0] == "19:30"
    assert chart.x_ticks[-1] == "19:48"
    assert len(chart.x_ticks) == 6


def test_empty_chart():
    chart = build_chart([("x", [None] * 10)], _TS, fmt="number")

    assert chart.empty


# --- The Monitoring tab built from these (honeypot-shelf) -----------------------


async def test_monitoring_tab_renders_chart_cards_and_services_table(client, db_session_factory):
    """The tab is debcontrol's layout: a toolbar, chart cards with their
    data for the hover script, and the services table on the page."""
    from app.db.models.company import Company
    from app.db.models.honeypot import Honeypot
    from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
    from app.db.models.honeypot_service import HoneypotService
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="charts-hp",
            host_key_fingerprint="SHA256:fake",
            monitoring_updated_at=now,
            services_updated_at=now,
        )
        db.add(honeypot)
        await db.flush()
        for i in range(6):
            db.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id,
                    sampled_at=now - timedelta(minutes=10 * (5 - i)),
                    cpu_percent=5.0 + i,
                    load1=0.1,
                    load5=0.1,
                    load15=0.1,
                    ram_used_bytes=400 * 1024**2,
                    ram_total_bytes=1024**3,
                    network_io=[{"iface": "eth0", "rx_bytes": 1000 * i, "tx_bytes": 500 * i}],
                    disk_io=[{"device": "mmcblk0", "read_bytes": 10 * i, "write_bytes": 90 * i}],
                    filesystems=[
                        {"mount": "/", "used_bytes": 5, "size_bytes": 10, "use_percent": 50}
                    ],
                    opencanary_active=True,
                )
            )
        db.add(
            HoneypotService(
                honeypot_id=honeypot.id,
                unit="opencanary.service",
                load_state="loaded",
                active_state="active",
                sub_state="running",
                description="OpenCanary",
            )
        )
        db.add(
            HoneypotService(
                honeypot_id=honeypot.id,
                unit="idle.service",
                load_state="loaded",
                active_state="inactive",
                sub_state="dead",
                description="Idle",
            )
        )
        await db.commit()
        honeypot_id = honeypot.id

    page = await client.get(f"/honeypots/{honeypot_id}/monitoring")

    assert page.status_code == 200
    assert 'class="monitoring-toolbar"' in page.text
    assert page.text.count('class="chart-card"') >= 7
    assert "data-chart=" in page.text
    # Received and sent are separate series now, as are read and write.
    assert "eth0 received" in page.text and "eth0 sent" in page.text
    assert "mmcblk0 read" in page.text and "mmcblk0 write" in page.text
    # The services table is on the page; an inactive unit starts hidden.
    assert 'id="services-table"' in page.text
    assert '<tr data-row-state="other" class="" hidden>' in page.text
    # The range picker is translated, not the raw English label.
    assert ">Last 24 hours<" in page.text


async def test_dashboard_trend_sums_every_company_per_day(client, db_session_factory):
    """Two companies' snapshots for the same day are one point on the trend
    charts (their sum), not two consecutive points."""
    from datetime import date

    from app.db.models.company_snapshot import CompanySnapshot
    from tests.conftest import create_company

    acme = await create_company(db_session_factory, name="Acme")
    beta = await create_company(db_session_factory, name="Beta")
    today = date.today()
    async with db_session_factory() as db:
        for offset, (a_events, b_events) in enumerate([(10, 5), (20, 7)]):
            day = today - timedelta(days=1 - offset)
            for company, events in ((acme, a_events), (beta, b_events)):
                db.add(
                    CompanySnapshot(
                        company_id=company.id,
                        snapshot_date=day,
                        honeypot_count=1,
                        honeypots_online=1,
                        event_count=events,
                    )
                )
        await db.commit()

    page = await client.get("/dashboard")

    assert page.status_code == 200
    assert ">Events per day<" in page.text and ">Honeypots with OpenCanary reporting<" in page.text
    # Two days -> two points, 15 and 27 events; both companies online -> 2.
    series = {}
    for raw in re.findall(r"data-chart='([^']*)'", page.text):
        for entry in json.loads(html.unescape(raw))["s"]:
            series[entry["label"]] = entry["v"]
    assert series["Events per day"] == [15, 27]
    assert series["Honeypots with OpenCanary reporting"] == [2, 2]
    assert "js/monitoring-chart.js" in page.text


async def test_activity_tab_uses_the_same_chart_cards(client, db_session_factory):
    from app.db.models.company import Company
    from app.db.models.honeypot import Honeypot
    from app.db.models.honeypot_event import HoneypotEvent
    from tests.conftest import create_company

    company = await create_company(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            companies=[await db.get(Company, company.id)],
            name="activity-hp",
            host_key_fingerprint="SHA256:fake",
            opencanary_log_polled_at=now,
        )
        db.add(honeypot)
        await db.flush()
        for i in range(5):
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type="4002",
                    occurred_at=now - timedelta(minutes=30 * i),
                    src_ip="203.0.113.9",
                    raw={},
                    source="ssh_poll",
                )
            )
        await db.commit()
        honeypot_id = honeypot.id

    page = await client.get(f"/honeypots/{honeypot_id}/status")

    assert page.status_code == 200
    assert 'class="monitoring-toolbar"' in page.text
    assert page.text.count('class="chart-card"') == 2
    assert 'id="activity-events-table"' in page.text
    assert ">Last 24 hours<" in page.text
    assert "js/monitoring-chart.js" in page.text and "trend-chart" not in page.text
