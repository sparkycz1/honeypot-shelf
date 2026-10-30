"""Retention purges delete in batches (one transaction each, oldest
first), and the time-series tables get time-ordered UUIDv7 primary keys."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import app.tasks.jobs as jobs
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample


@pytest.fixture
def counted_commits(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> list[int]:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(jobs, "_DELETE_BATCH_SIZE", 3)
    commits = [0]
    real_commit = AsyncSession.commit

    async def counting_commit(self: AsyncSession) -> None:
        commits[0] += 1
        await real_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", counting_commit)
    return commits


async def _count(db_session_factory: Any, model: Any) -> int:
    async with db_session_factory() as session:
        return int(
            (await session.execute(select(func.count()).select_from(model))).scalar_one()
        )


async def _audit_details(db_session_factory: Any, action: str) -> Any:
    async with db_session_factory() as session:
        entry = (
            await session.execute(select(AuditLogEntry).where(AuditLogEntry.action == action))
        ).scalar_one()
        return entry.details


async def test_sample_purge_deletes_everything_in_batches(
    db_session_factory: Any, counted_commits: list[int]
) -> None:
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        honeypot = Honeypot(name="pi-1")
        session.add(honeypot)
        await session.flush()
        for days in range(1, 21):  # 20 rows each, days 10-20 past a 10-day retention
            at = now - timedelta(days=days, hours=1)
            session.add(HoneypotMonitoringSample(honeypot_id=honeypot.id, sampled_at=at))
            session.add(
                HoneypotReachabilitySample(honeypot_id=honeypot.id, checked_at=at, reachable=True)
            )
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_history_retention_days = 10
        await session.commit()
    counted_commits[0] = 0

    await jobs._purge_old_monitoring_samples()

    assert await _count(db_session_factory, HoneypotMonitoringSample) == 9
    assert await _count(db_session_factory, HoneypotReachabilitySample) == 9
    assert await _audit_details(db_session_factory, "monitoring_samples.purge") == {
        "deleted_count": 22
    }
    # 11 rows per table in batches of 3 (4 commits each), plus the audit entry
    assert counted_commits[0] >= 9


async def test_event_purge_deletes_everything_in_batches(
    db_session_factory: Any, counted_commits: list[int]
) -> None:
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        honeypot = Honeypot(name="pi-2")
        session.add(honeypot)
        await session.flush()
        for days in range(1, 11):
            session.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type="4002",
                    occurred_at=now - timedelta(days=days * 20),
                    raw={},
                    source="ssh_poll",
                )
            )
        await session.commit()
    counted_commits[0] = 0

    await jobs._purge_old_events()

    # default retention is 90 days: rows at 100..200 days go, 20..80 stay
    assert await _count(db_session_factory, HoneypotEvent) == 4
    details = await _audit_details(db_session_factory, "honeypot_events.purge")
    assert details["deleted_count"] == 6
    assert counted_commits[0] >= 3


async def test_time_series_rows_get_uuid7_ids(db_session_factory: Any) -> None:
    async with db_session_factory() as session:
        honeypot = Honeypot(name="pi-3")
        session.add(honeypot)
        await session.flush()
        sample = HoneypotMonitoringSample(honeypot_id=honeypot.id, sampled_at=datetime.now(UTC))
        session.add(sample)
        await session.commit()
        assert sample.id.version == 7
        assert honeypot.id.version == 4
