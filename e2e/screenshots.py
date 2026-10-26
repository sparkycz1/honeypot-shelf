"""Screenshots for the README and the wiki, taken from the real app.

Starts the same in-memory app as `e2e/serve.py`, adds a few made-up
companies, honeypots and attacks so the pages look like a working fleet,
then saves one PNG per page into `docs/screenshots/`:

    uv sync --group e2e
    uv run playwright install chromium
    uv run python -m e2e.screenshots

Every name, address and attack below is invented; the addresses come from
the documentation ranges (RFC 5737), so no real network appears.
"""

from __future__ import annotations

import asyncio
import os
import random
import threading
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

# First: `serve` sets the environment the app's settings need on import.
from e2e import serve  # isort: skip

import uvicorn
from celery import Task
from playwright.sync_api import Page, sync_playwright
from sqlalchemy import delete, select

from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.geoip_database import SINGLETON_ID as GEOIP_ID
from app.db.models.geoip_database import GeoipDatabase
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_tag import Tag
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.session import get_db
from app.main import app
from tests.conftest import FakeRedis

PORT = 8767
BASE = f"http://127.0.0.1:{PORT}"
OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"

# Where the made-up attacks come from: country, city, latitude, longitude.
ORIGINS = [
    ("CN", "China", "Beijing", 39.9, 116.4),
    ("US", "United States", "Ashburn", 39.0, -77.5),
    ("RU", "Russia", "Moscow", 55.8, 37.6),
    ("NL", "Netherlands", "Amsterdam", 52.4, 4.9),
    ("BR", "Brazil", "São Paulo", -23.5, -46.6),
    ("IN", "India", "Mumbai", 19.1, 72.9),
    ("DE", "Germany", "Frankfurt", 50.1, 8.7),
    ("VN", "Vietnam", "Hanoi", 21.0, 105.8),
    ("KR", "South Korea", "Seoul", 37.6, 127.0),
    ("SG", "Singapore", "Singapore", 1.35, 103.8),
]
# OpenCanary log types, weighted roughly like a real internet-facing decoy.
EVENT_TYPES = ["4002"] * 8 + ["5001"] * 5 + ["3000"] * 3 + ["6001"] * 2 + ["2000", "8001", "14001"]

HONEYPOTS = [
    # name, company, os_id, address, reachable, OpenCanary reporting, updates
    ("acme-dmz-01", "Acme", "raspbian", "198.51.100.11", True, True, 0),
    ("acme-office-02", "Acme", "debian", "198.51.100.12", True, True, 4),
    ("globex-branch-01", "Globex", "raspbian", "198.51.100.21", True, True, 0),
    ("globex-lab-02", "Globex", "ubuntu", "198.51.100.22", True, False, 7),
    ("globex-wh-03", "Globex", "raspbian", "198.51.100.23", False, False, 0),
    ("initech-hq-01", "Initech", "debian", "198.51.100.31", True, True, 2),
    ("initech-vpn-02", "Initech", "raspbian", "198.51.100.32", True, True, 0),
]

# (file name, path, height in pixels) — "{hp}" in a path is the first demo
# honeypot's id, "{sample}" the one `serve` adds with monitoring history;
# the page is cut off at that height.
PAGES = [
    ("dashboard", "/dashboard", 1500),
    ("honeypots", "/honeypots", 780),
    ("honeypot-overview", "/honeypots/{hp}", 1200),
    ("honeypot-monitoring", "/honeypots/{sample}/monitoring", 1300),
    ("honeypot-activity", "/honeypots/{hp}/status", 1300),
    ("events", "/events", 1000),
    ("map", "/map", 1000),
    ("scheduling-calendar", "/scheduling/calendar", 900),
    ("initialize", "/initialize", 900),
    ("api", "/api", 900),
]


async def seed_demo() -> tuple[str, str]:
    """The `serve` data plus a small made-up fleet; returns the first demo
    honeypot's id and the id of the one `serve` added."""
    rng = random.Random(7)  # noqa: S311 - made-up demo data, not a secret
    now = datetime.now(UTC).replace(microsecond=0)
    async with serve.factory() as db:
        sample = await db.scalar(select(Honeypot))
        assert sample is not None
        sample_id = str(sample.id)
        companies = {c.name: c for c in (await db.scalars(select(Company))).all()}
        for name in ("Globex", "Initech"):
            companies[name] = Company(name=name)
            db.add(companies[name])
        # The Map only draws once a GeoIP database is in; the events below
        # already carry their location, so a placeholder is enough.
        db.add(GeoipDatabase(id=GEOIP_ID, mmdb_data=b"demo", source="upload", updated_at=now))
        tags = {name: Tag(name=name) for name in ("dmz", "office", "pilot")}
        db.add_all(tags.values())
        await db.flush()

        first_id = ""
        for name, company, os_id, address, reachable, reporting, updates in HONEYPOTS:
            honeypot = Honeypot(
                companies=[companies[company]],
                name=name,
                discovered_hostname=name,
                location=f"{company} — {name.split('-')[1]}",
                ip_address=address,
                port=22,
                username="honeypotshelf",
                auth_method=AuthMethod.SSH_KEY,
                host_key_fingerprint="SHA256:demo",
                os_id=os_id,
                os_version={
                    "raspbian": "Raspberry Pi OS 13 (trixie)",
                    "debian": "Debian GNU/Linux 13 (trixie)",
                    "ubuntu": "Ubuntu 26.04 LTS",
                }[os_id],
                kernel_version="6.12.47+rpt-rpi-v8",
                cpu_architecture="aarch64",
                cpu_cores=4,
                cpu_model="Cortex-A76",
                ram_bytes=4 * 1024**3,
                uptime_seconds=rng.randint(2, 40) * 86400,
                is_reachable=reachable,
                last_ping_at=now,
                last_seen_at=now - timedelta(minutes=2) if reporting else now - timedelta(days=2),
                opencanary_log_polled_at=now,
                facts_updated_at=now,
                updates_checked_at=now,
                upgradable_count=updates,
                security_upgradable_count=updates // 2,
                tags=[tags["dmz"] if "dmz" in name else tags["office"]]
                + ([tags["pilot"]] if name.endswith("01") else []),
                hw_vendor="Raspberry Pi Ltd" if os_id == "raspbian" else "Dell Inc.",
                hw_model="Raspberry Pi 5 Model B" if os_id == "raspbian" else "OptiPlex 3000",
                purchase_date=date(2025, 3, 1),
                warranty_until=date(2028, 3, 1),
            )
            db.add(honeypot)
            await db.flush()
            first_id = first_id or str(honeypot.id)
            if not reporting:
                continue
            for _ in range(rng.randint(60, 160)):
                code, country, city, lat, lon = rng.choice(ORIGINS)
                db.add(
                    HoneypotEvent(
                        honeypot_id=honeypot.id,
                        event_type=rng.choice(EVENT_TYPES),
                        occurred_at=now - timedelta(minutes=rng.randint(1, 24 * 60)),
                        src_ip=f"203.0.113.{rng.randint(1, 254)}",
                        src_port=rng.randint(30000, 65000),
                        dst_port=22,
                        src_country_code=code,
                        src_country_name=country,
                        src_city_name=city,
                        src_latitude=lat + rng.uniform(-1, 1),
                        src_longitude=lon + rng.uniform(-1, 1),
                        raw={},
                        source="ssh_poll",
                    )
                )

        # A few schedules and a maintenance window for Scheduling's calendar.
        for name, action, cron, params, company in (
            (
                "Security updates",
                "system_update",
                "0 3 * * *",
                {"strategy": "security"},
                "Acme",
            ),
            (
                "Weekly full upgrade",
                "system_update",
                "30 4 * * 0",
                {"strategy": "full_upgrade", "reboot": "if_required", "rollout": "one_by_one"},
                "Globex",
            ),
            ("Monday reboot", "reboot", "0 5 * * 1", None, "Initech"),
        ):
            db.add(
                ScheduledTask(
                    name=name,
                    action=action,
                    action_params=params,
                    target_type=ScheduleTargetType.COMPANY,
                    owner_company_id=companies[company].id,
                    cron_expression=cron,
                    timezone="Europe/Prague",
                )
            )
        window_start = datetime.combine(date.today() + timedelta(days=3), datetime.min.time(), UTC)
        db.add(
            MaintenanceWindow(
                owner_company_id=companies["Globex"].id,
                name="Switch replacement",
                starts_at=window_start + timedelta(hours=18),
                ends_at=window_start + timedelta(hours=22),
                all_honeypots=True,
            )
        )

        # A month of daily rollups for the Dashboard's trend charts, in
        # place of the week `serve` adds.
        await db.execute(delete(CompanySnapshot))
        sizes = {"Acme": 2, "Globex": 3, "Initech": 2}
        for company_name, size in sizes.items():
            for days_ago in range(30):
                db.add(
                    CompanySnapshot(
                        company_id=companies[company_name].id,
                        snapshot_date=date.today() - timedelta(days=days_ago),
                        honeypot_count=size,
                        honeypots_online=size - (1 if days_ago < 3 and size == 3 else 0),
                        honeypots_reachable=size,
                        event_count=rng.randint(150, 420) + 8 * (30 - days_ago),
                        needs_updates=rng.randint(0, size),
                        needs_security_updates=rng.randint(0, 1),
                        needs_reboot=0,
                    )
                )
        await db.commit()
    return first_id, sample_id


def _settle(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(800)


def capture(token: str, honeypot_id: str, sample_id: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        # CHROMIUM_PATH: a browser already on the machine instead of
        # Playwright's own download.
        browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            device_scale_factor=1,
            color_scheme="dark",
        )
        context.add_cookies([{"name": "session", "value": token, "url": BASE}])
        page = context.new_page()
        for name, path, height in PAGES:
            page.goto(BASE + path.format(hp=honeypot_id, sample=sample_id))
            _settle(page)
            target = OUT / f"{name}.png"
            full_height = page.evaluate("document.documentElement.scrollHeight")
            page.screenshot(
                path=str(target),
                full_page=True,
                clip={"x": 0, "y": 0, "width": 1440, "height": min(height, full_height)},
            )
            print(f"saved {target.relative_to(OUT.parent.parent)}")
        browser.close()


def main() -> None:
    token = asyncio.run(serve.seed())
    honeypot_id, sample_id = asyncio.run(seed_demo())
    Task.apply_async = serve._fake_apply_async
    app.dependency_overrides[get_db] = serve._get_db
    app.state.redis = FakeRedis()
    app.state.db_session_factory = serve.factory
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="critical", lifespan="off")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.1)
    try:
        capture(token, honeypot_id, sample_id)
    finally:
        server.should_exit = True
        thread.join()


if __name__ == "__main__":
    main()
