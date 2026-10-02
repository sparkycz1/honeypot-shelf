"""Disk-full forecast: the trend math (`app.services.disk_forecast`, ported
from debcontrol), the hourly job that stores it on `Honeypot.disk_forecast`,
and where it shows (Monitoring tab, REST API)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

import app.tasks.jobs as jobs
from app.auth.api_tokens import create_api_token
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.user import User
from app.services.disk_forecast import forecast_filesystems, soonest_full_days
from tests.conftest import create_company

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
GB = 1024**3


def _fs(used: int, size: int = 100 * GB, mount: str = "/") -> list[dict[str, object]]:
    return [{"mount": mount, "used_bytes": used, "size_bytes": size, "use_percent": 0}]


def test_growing_disk_forecast():
    # +1 GB/day for 6 days, 60 GB used of 100 at the end → 40 days left.
    samples = [(NOW - timedelta(days=6 - d), _fs((54 + d) * GB)) for d in range(7)]

    forecast = forecast_filesystems(samples, NOW)

    assert forecast["/"]["bytes_per_day"] == GB
    assert forecast["/"]["days_until_full"] == pytest.approx(40.0)


def test_shrinking_or_flat_disk_has_no_estimate():
    samples = [(NOW - timedelta(hours=10 - h), _fs((50 - h) * GB)) for h in range(10)]

    assert forecast_filesystems(samples, NOW)["/"]["days_until_full"] is None


def test_full_disk_is_zero_days():
    samples = [(NOW - timedelta(hours=10 - h), _fs(100 * GB)) for h in range(10)]

    assert forecast_filesystems(samples, NOW)["/"]["days_until_full"] == 0.0


def test_too_little_history_is_skipped():
    few = [(NOW - timedelta(hours=h), _fs(50 * GB)) for h in range(3)]
    short = [(NOW - timedelta(minutes=10 * m), _fs(50 * GB)) for m in range(10)]

    assert forecast_filesystems(few, NOW) == {}
    assert forecast_filesystems(short, NOW) == {}


def test_malformed_samples_are_ignored():
    bad: list[dict[str, Any]] = [{"mount": None}, {"mount": "/", "size_bytes": 0}]
    samples: list[tuple[datetime, list[dict[str, Any]] | None]] = [
        (NOW - timedelta(hours=10 - h), bad) for h in range(10)
    ]

    assert forecast_filesystems([*samples, (NOW, None)], NOW) == {}


def test_soonest_full_days_picks_the_minimum():
    assert soonest_full_days(
        {"/": {"days_until_full": 40.0}, "/srv": {"days_until_full": 5.5}, "/x": {}}
    ) == 5.5
    assert soonest_full_days(None) is None


async def _honeypot_with_week_of_samples(db_session_factory) -> uuid.UUID:
    company = await create_company(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        honeypot = Honeypot(
            companies=[await session.get(Company, company.id)],
            name="fc",
            host_key_fingerprint="SHA256:fakefingerprint",
            monitoring_updated_at=now,
        )
        session.add(honeypot)
        await session.flush()
        for d in range(7):
            session.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id,
                    sampled_at=now - timedelta(days=6 - d),
                    filesystems=_fs((54 + d) * GB),
                )
            )
        await session.commit()
        return honeypot.id


async def test_job_stores_the_forecast(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _honeypot_with_week_of_samples(db_session_factory)

    result = await jobs._forecast_honeypot_disks(str(honeypot_id))

    assert result == {"ok": True, "mounts": 1}
    async with db_session_factory() as session:
        stored = await session.get(Honeypot, honeypot_id)
        assert stored is not None
        assert stored.disk_forecast is not None
        assert stored.disk_forecast["/"]["days_until_full"] == pytest.approx(40.0, abs=0.5)


async def test_job_handles_unknown_honeypot(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    assert (await jobs._forecast_honeypot_disks(str(uuid.uuid4())))["ok"] is False


async def test_sweep_enqueues_one_job_per_monitored_honeypot(
    db_session_factory, monkeypatch, celery_calls
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _honeypot_with_week_of_samples(db_session_factory)
    async with db_session_factory() as session:
        session.add(Honeypot(name="never-monitored"))
        await session.commit()

    await jobs._forecast_all_honeypot_disks()

    calls = [c for c in celery_calls if c[0] == "app.tasks.jobs.forecast_honeypot_disks"]
    assert [c[1] for c in calls] == [(str(honeypot_id),)]


async def test_monitoring_tab_and_api_show_the_forecast(
    client, db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    honeypot_id = await _honeypot_with_week_of_samples(db_session_factory)
    await jobs._forecast_honeypot_disks(str(honeypot_id))

    page = await client.get(f"/honeypots/{honeypot_id}/monitoring")
    assert page.status_code == 200
    assert "full in ~40 days" in page.text

    async with db_session_factory() as session:
        user = (await session.execute(select(User))).scalars().first()
        assert user is not None
        _token, raw_token = await create_api_token(session, user, name="t", expires_at=None)
        await session.commit()
    response = await client.get(
        f"/api/v1/honeypots/{honeypot_id}", headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert response.status_code == 200
    assert response.json()["disk_forecast"]["/"]["days_until_full"] == pytest.approx(40.0, abs=0.5)
