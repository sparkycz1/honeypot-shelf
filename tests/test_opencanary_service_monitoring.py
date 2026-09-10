"""The Monitoring tab's "OpenCanary service" panel — `systemctl is-active
opencanary`, piggybacked onto the same round trip `MONITORING_COMMAND`
already makes, through to the historized uptime-style series the template
charts (`app.services.monitoring_history.MonitoringHistory.
opencanary_uptime_percent`). Regression guard for a real feature request:
before this, only the Activity tab's event flow (`Honeypot.last_seen_at`)
and the Services summary's point-in-time check reflected OpenCanary's own
health — no historized "was the unit itself active" signal existed."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.services.monitoring_history import build_monitoring_history
from app.ssh.monitoring import parse_monitoring_output
from app.tasks.jobs import _sample_honeypot_monitoring
from tests.conftest import create_company

pytestmark = pytest.mark.asyncio


def _fake_output(opencanary_section: str) -> str:
    return (
        "===CPU===\n50.0\n"
        "===LOAD===\n0.1 0.2 0.3\n"
        "===RAM_KB===\n1000 500\n"
        "===NET===\n"
        "===DISKIO===\n"
        "===FILESYSTEMS===\n"
        "===FAILED_SERVICES===\n0\n"
        f"===OPENCANARY===\n{opencanary_section}\n"
    )


def test_parse_monitoring_output_reads_opencanary_active():
    sample = parse_monitoring_output(_fake_output("active"))
    assert sample["opencanary_active"] is True


def test_parse_monitoring_output_reads_opencanary_inactive():
    sample = parse_monitoring_output(_fake_output("inactive"))
    assert sample["opencanary_active"] is False


def test_parse_monitoring_output_no_systemd_is_none_not_inactive():
    sample = parse_monitoring_output(_fake_output(""))
    assert sample["opencanary_active"] is None


def test_build_monitoring_history_computes_opencanary_uptime_percent():
    now = datetime.now(UTC)
    samples = [
        HoneypotMonitoringSample(
            honeypot_id=uuid.uuid4(), sampled_at=now - timedelta(minutes=2), opencanary_active=True
        ),
        HoneypotMonitoringSample(
            honeypot_id=uuid.uuid4(), sampled_at=now - timedelta(minutes=1), opencanary_active=False
        ),
    ]
    history = build_monitoring_history(samples, "24h")
    assert history.opencanary_uptime_percent == [100.0, 0.0]
    assert history.latest_opencanary_active is False


def test_build_monitoring_history_none_opencanary_active_is_a_gap_not_zero():
    now = datetime.now(UTC)
    samples = [
        HoneypotMonitoringSample(
            honeypot_id=uuid.uuid4(), sampled_at=now, opencanary_active=None
        ),
    ]
    history = build_monitoring_history(samples, "24h")
    assert history.opencanary_uptime_percent == [None]
    assert history.latest_opencanary_active is None


async def test_sample_honeypot_monitoring_stores_opencanary_active(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(
            company_id=company.id,
            name="acme-honey1",
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        db.add(honeypot)
        await db.commit()
        await db.refresh(honeypot)
        honeypot_id = honeypot.id

    async def fake_gather(
        honeypot: object, secret: object, timeout_seconds: int
    ) -> dict[str, object]:
        return {
            "cpu_percent": 10.0,
            "load1": 0.1,
            "load5": 0.2,
            "load15": 0.3,
            "ram_used_bytes": 100,
            "ram_total_bytes": 200,
            "network_io": [],
            "disk_io": [],
            "filesystems": [],
            "failed_services_count": 0,
            "opencanary_active": True,
        }

    monkeypatch.setattr("app.tasks.jobs.gather_monitoring_sample", fake_gather)

    result = await _sample_honeypot_monitoring(str(honeypot_id))

    assert result == {"ok": True}
    async with db_session_factory() as db:
        rows = (await db.execute(select(HoneypotMonitoringSample))).scalars().all()
        assert len(rows) == 1
        assert rows[0].opencanary_active is True
