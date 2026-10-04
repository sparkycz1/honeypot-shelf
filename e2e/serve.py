"""The app for the browser smoke test (`e2e/test_pages.py`): the real
FastAPI application on an in-memory SQLite database with a small, fixed
set of data — wired the same way `tests/conftest.py` wires it, so it needs
no Postgres, Redis or Celery. Background tasks a page waits for return a
canned result instead of opening an SSH session.

    python -m e2e.serve [port]

Prints `SESSION_TOKEN=<token>` (a signed-in superadmin session for the
`session` cookie) once the data is in, then serves on 127.0.0.1. Also
handy for looking at a change by hand. Same layout as debcontrol's.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncGenerator
from datetime import UTC, date, datetime, timedelta
from typing import Any

os.environ.setdefault("SECRET_KEY", "e2e-only-secret-key-not-for-real-use-0000000000")
os.environ.setdefault("ENCRYPTION_KEY", "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://e2e:e2e@localhost/e2e")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("POSTGRES_PASSWORD", "e2e")
os.environ.setdefault("REDIS_PASSWORD", "e2e")
os.environ.setdefault("INFORM_TOKEN", "e2e-only-inform-token-not-for-real-use-0000000000")

import uvicorn
from celery import Task
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.auth.sessions import create_session
from app.db.base import Base
from app.db.models.company import Company
from app.db.models.company_snapshot import CompanySnapshot
from app.db.models.honeypot import AuthMethod, Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.honeypot_monitoring_sample import HoneypotMonitoringSample
from app.db.models.honeypot_reachability_sample import (
    HoneypotReachabilitySample,
)
from app.db.models.honeypot_service import HoneypotService
from app.db.models.user import AuthProvider, User
from app.db.session import get_db
from app.main import app
from tests.conftest import FakeAsyncResult, FakeRedis

DEFAULT_PORT = 8766

engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
factory = async_sessionmaker(engine, expire_on_commit=False)


def _fake_apply_async(
    self: Task, args: Any = None, kwargs: Any = None, **options: Any
) -> FakeAsyncResult:
    """No worker here: a task a route waits for "succeeds" at once."""
    return FakeAsyncResult(self.name, {"ok": True})


async def seed() -> str:
    """Create the schema and the sample data; returns a session token."""
    now = datetime.now(UTC).replace(microsecond=0)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with factory() as db:
        user = User(
            username="admin",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            is_superadmin=True,
            api_access_enabled=True,
        )
        company = Company(name="Acme")
        db.add_all([user, company])
        await db.flush()
        honeypot = Honeypot(
            companies=[company],
            name="acme-honey1",
            ip_address="192.0.2.10",
            port=22,
            username="honeypotshelf",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:e2e",
            is_reachable=True,
            monitoring_updated_at=now,
            services_updated_at=now,
            last_ping_at=now,
            opencanary_log_polled_at=now,
            last_seen_at=now,
        )
        db.add(honeypot)
        await db.flush()

        gib = 1024**3
        for k in range(60):
            at = now - timedelta(minutes=2 * (59 - k))
            db.add(
                HoneypotMonitoringSample(
                    honeypot_id=honeypot.id,
                    sampled_at=at,
                    cpu_percent=2.0 + (k % 7),
                    load1=0.1,
                    load5=0.1,
                    load15=0.05,
                    ram_used_bytes=int(0.4 * gib),
                    ram_total_bytes=gib,
                    network_io=[{"iface": "eth0", "rx_bytes": 40_000 * k, "tx_bytes": 15_000 * k}],
                    disk_io=[
                        {"device": "mmcblk0", "read_bytes": 2_000 * k, "write_bytes": 30_000 * k}
                    ],
                    filesystems=[
                        {
                            "mount": "/",
                            "used_bytes": 5 * gib,
                            "size_bytes": 29 * gib,
                            "use_percent": 18,
                        }
                    ],
                    opencanary_active=True,
                )
            )
            db.add(
                HoneypotReachabilitySample(
                    honeypot_id=honeypot.id, checked_at=at, reachable=True, latency_ms=18.0 + k % 5
                )
            )
            db.add(
                HoneypotEvent(
                    honeypot_id=honeypot.id,
                    event_type=("4002", "3000", "5001")[k % 3],
                    occurred_at=at,
                    src_ip=f"203.0.113.{k + 1}",
                    src_port=40000 + k,
                    raw={},
                    source="ssh_poll",
                )
            )
        for days_ago in range(7):
            db.add(
                CompanySnapshot(
                    company_id=company.id,
                    snapshot_date=date.today() - timedelta(days=days_ago),
                    honeypot_count=1,
                    honeypots_online=1,
                    honeypots_reachable=1,
                    event_count=100 + 10 * days_ago,
                    needs_updates=0,
                    needs_security_updates=0,
                    needs_reboot=0,
                )
            )
        for unit, active, sub in (
            ("opencanary.service", "active", "running"),
            ("ssh.service", "active", "running"),
            ("logrotate.service", "failed", "failed"),
        ):
            db.add(
                HoneypotService(
                    honeypot_id=honeypot.id,
                    unit=unit,
                    load_state="loaded",
                    active_state=active,
                    sub_state=sub,
                    description=unit,
                )
            )
        await db.flush()
        _session, token = await create_session(db, user, ip_address=None, user_agent=None)
        await db.commit()
    return token


async def _get_db() -> AsyncGenerator[AsyncSession]:
    async with factory() as session:
        yield session


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    token = asyncio.run(seed())
    Task.apply_async = _fake_apply_async  # type: ignore[method-assign]
    app.dependency_overrides[get_db] = _get_db
    app.state.redis = FakeRedis()
    app.state.db_session_factory = factory
    print("SESSION_TOKEN=" + token, flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")


if __name__ == "__main__":
    main()
