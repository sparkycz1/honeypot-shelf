"""TimescaleDB support (app/db/timescale.py, 0.87.0): off on anything
without the extension, the time column in every history primary key,
whole-day chunk drops in the retention purges, and the Settings page/API
showing it. The SQL against a real TimescaleDB is exercised by hand
against the bundled `timescaledb` image (wiki/Development), not here."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import asyncpg
import pytest
from sqlalchemy import inspect, select

import app.tasks.jobs as jobs
from app.auth.api_tokens import create_api_token
from app.core.app_settings import get_or_create_app_settings
from app.db import timescale
from app.db.base import Base
from app.db.models.audit_log import AuditLogEntry
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_reachability_sample import HoneypotReachabilitySample
from app.db.models.user import User


def test_time_column_is_part_of_every_history_primary_key() -> None:
    models: list[tuple[type[Base], timescale.Hypertable]] = [
        (HoneypotMonitoringSample, timescale.MONITORING),
        (HoneypotReachabilitySample, timescale.REACHABILITY),
        (HoneypotEvent, timescale.EVENTS),
    ]
    for model, table in models:
        assert model.__tablename__ == table.table
        assert [c.name for c in inspect(model).primary_key] == ["id", table.time_column]


def test_events_are_compressed_only_after_a_month() -> None:
    # The Events page searches recent events by source address and type;
    # compressed chunks would make those searches slow.
    assert timescale.EVENTS.compress_after_days == 30
    assert timescale.MONITORING.compress_after_days == 7
    assert timescale.REACHABILITY.compress_after_days == 7


async def test_everything_is_a_no_op_without_timescaledb(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(timescale, "_enabled", None)
    async with db_session_factory() as session:
        assert await timescale.enabled(session) is False
        assert await timescale.describe(session) is None


async def _honeypot(session: Any, name: str, retention: int | None) -> Honeypot:
    honeypot = Honeypot(name=name, monitoring_history_retention_days=retention)
    session.add(honeypot)
    await session.flush()
    return honeypot


async def _purge_audit(db_session_factory: Any, action: str) -> AuditLogEntry | None:
    async with db_session_factory() as session:
        return (
            await session.execute(select(AuditLogEntry).where(AuditLogEntry.action == action))
        ).scalar_one_or_none()


@pytest.mark.parametrize(
    ("default", "overrides", "expected_days"),
    [
        (30, [None, 10], 30),  # longest wins; the shorter goes row by row
        (30, [60, None], 60),
        (None, [10, None], None),  # one honeypot keeps its history forever
        (None, [10, 20], 20),
    ],
)
async def test_sample_purge_drops_whole_days_only_where_every_honeypot_allows(
    db_session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    default: int | None,
    overrides: list[int | None],
    expected_days: int | None,
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(timescale, "_enabled", True)
    calls: list[tuple[str, datetime]] = []

    async def fake_drop(session: Any, table: timescale.Hypertable, older_than: datetime) -> int:
        calls.append((table.table, older_than))
        return 2

    monkeypatch.setattr(timescale, "drop_old_chunks", fake_drop)
    async with db_session_factory() as session:
        for index, days in enumerate(overrides):
            await _honeypot(session, f"pi-{index}", days)
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_history_retention_days = default
        await session.commit()

    before = datetime.now(UTC)
    await jobs._purge_old_monitoring_samples()

    audit = await _purge_audit(db_session_factory, "monitoring_samples.purge")
    if expected_days is None:
        assert calls == []
        assert audit is None
        return
    assert {table for table, _ in calls} == {
        timescale.MONITORING.table,
        timescale.REACHABILITY.table,
    }
    expected = before - timedelta(days=expected_days)
    for _, older_than in calls:
        assert abs((older_than - expected).total_seconds()) < 60
    assert audit is not None
    assert audit.details is not None
    assert audit.details["chunks_dropped"] == 4
    assert "4 whole day chunks" in audit.summary


async def test_event_purge_drops_whole_days_then_the_rest(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(timescale, "_enabled", True)
    calls: list[tuple[str, datetime]] = []

    async def fake_drop(session: Any, table: timescale.Hypertable, older_than: datetime) -> int:
        calls.append((table.table, older_than))
        return 1

    monkeypatch.setattr(timescale, "drop_old_chunks", fake_drop)
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        honeypot = await _honeypot(session, "pi", None)
        app_settings = await get_or_create_app_settings(session)
        app_settings.event_retention_days = 30
        # The rest of the oldest day, which no whole chunk covers.
        for days in (31, 5):
            session.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type="4002",
                    occurred_at=now - timedelta(days=days),
                    raw={},
                )
            )
        await session.commit()

    await jobs._purge_old_events()

    assert [table for table, _ in calls] == [timescale.EVENTS.table]
    assert abs((calls[0][1] - (now - timedelta(days=30))).total_seconds()) < 60
    async with db_session_factory() as session:
        left = (await session.execute(select(HoneypotEvent))).scalars().all()
    assert len(left) == 1
    audit = await _purge_audit(db_session_factory, "honeypot_events.purge")
    assert audit is not None
    assert audit.details == {"deleted_count": 1, "retention_days": 30, "chunks_dropped": 1}
    assert "1 whole day chunk" in audit.summary


async def test_settings_page_and_api_show_timescaledb(
    client: Any, login_as: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    info = {
        "version": "2.31.0",
        "compress_after_days": {
            "honeypot_monitoring_samples": 7,
            "honeypot_reachability_samples": 7,
            "honeypot_events": 30,
        },
    }

    async def fake_describe(session: Any) -> dict[str, Any]:
        return info

    page = await client.get("/settings?tab=checks")
    assert page.status_code == 200
    assert "TimescaleDB" not in page.text

    monkeypatch.setattr(timescale, "describe", fake_describe)
    page = await client.get("/settings?tab=checks")
    assert "TimescaleDB 2.31.0" in page.text
    assert "OpenCanary events after 30 days" in page.text

    user = await login_as(client, username="api-admin", is_superadmin=True, api_access_enabled=True)
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        assert db_user is not None
        _token, raw_token = await create_api_token(db, db_user, name="t", expires_at=None)
    response = await client.get(
        "/api/v1/settings", headers={"Authorization": f"Bearer {raw_token}"}
    )
    assert response.json()["timescaledb"] == info


class _Result:
    def __init__(self, row: tuple[str, str] | None) -> None:
        self._row = row

    def first(self) -> tuple[str, str] | None:
        return self._row


class _Conn:
    def __init__(self, row: tuple[str, str] | None) -> None:
        self.row = row

    async def execute(self, _statement: Any) -> _Result:
        return _Result(self.row)


class _Bare:
    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.statements: list[str] = []
        self.closed = False

    async def execute(self, sql: str) -> None:
        if self.fail:
            raise asyncpg.InsufficientPrivilegeError("must be owner of extension")
        self.statements.append(sql)

    async def close(self) -> None:
        self.closed = True


def _fake_connect(monkeypatch: pytest.MonkeyPatch, bare: _Bare) -> list[str]:
    dsns: list[str] = []

    async def connect(dsn: str) -> _Bare:
        dsns.append(dsn)
        return bare

    monkeypatch.setattr(asyncpg, "connect", connect)
    return dsns


URL = "postgresql+asyncpg://app:secret@db:5432/honeypotshelf"


@pytest.mark.parametrize("row", [None, ("2.32.0", "2.32.0")])
async def test_extension_update_is_skipped_when_not_needed(
    monkeypatch: pytest.MonkeyPatch, row: tuple[str, str] | None
) -> None:
    dsns = _fake_connect(monkeypatch, _Bare(fail=False))
    assert await timescale.update_extension(_Conn(row), URL) is None  # type: ignore[arg-type]
    assert dsns == []


async def test_extension_update_runs_first_on_a_bare_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # After a new TimescaleDB image the database stays on the old extension
    # version until ALTER EXTENSION ... UPDATE, which must be the first
    # statement of its session — hence a bare asyncpg connection.
    bare = _Bare(fail=False)
    dsns = _fake_connect(monkeypatch, bare)
    updated = await timescale.update_extension(_Conn(("2.31.0", "2.32.0")), URL)  # type: ignore[arg-type]
    assert updated == "2.31.0 -> 2.32.0"
    assert dsns == ["postgresql://app:secret@db:5432/honeypotshelf"]
    assert bare.statements == ["ALTER EXTENSION timescaledb UPDATE"]
    assert bare.closed


async def test_extension_update_without_ownership_only_warns(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    bare = _Bare(fail=True)
    _fake_connect(monkeypatch, bare)
    updated = await timescale.update_extension(_Conn(("2.31.0", "2.32.0")), URL)  # type: ignore[arg-type]
    assert updated is None
    assert bare.closed
    assert "ALTER EXTENSION timescaledb UPDATE" in caplog.text
    assert "secret" not in caplog.text
