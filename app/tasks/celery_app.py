"""Celery application: the app's one and only background task queue.

Run (both handled by docker-compose.yml — the `worker` and `beat` services):

    celery -A app.tasks.celery_app worker --loglevel=info --concurrency=4
    celery -A app.tasks.celery_app beat   --loglevel=info

Broker *and* result backend are the same Redis instance the rest of the app
already uses (`REDIS_URL`). Unlike debcontrol, event ingestion itself
(`app/web/routes/ingest.py`) is a plain synchronous DB write on the web
process — there's no SSH round trip or apt run to fan out, so there's
nothing time-consuming enough on the ingest path to justify enqueueing it.
Celery here is only for the daily housekeeping sweeps below.

See `app.db.session`'s module docstring and the fork-safety handler below
for why the DB engine is rebuilt in every worker child — same reasoning
and same fix as debcontrol's `app/tasks/celery_app.py`, copied verbatim:
Celery's prefork pool means naively importing `app.db.session` at module
load time would leave every forked worker child sharing the parent's
asyncpg connection pool, which fails in ways invisible to the (SQLite-based)
test suite and only bites a real Postgres deployment.
"""

from __future__ import annotations

import logging

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)

settings = get_settings()
configure_logging(settings.log_level)

celery_app = Celery(
    "honeyhive",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.jobs"],
)

celery_app.conf.update(
    # JSON only — never pickle. A compromised Redis can't hand the worker
    # arbitrary objects to deserialize.
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,
    worker_prefetch_multiplier=1,
    result_expires=3600,
)

celery_app.conf.beat_schedule = {
    # Once a day: purge honeypot_events older than EVENT_RETENTION_DAYS,
    # audit_log_entries older than AppSettings.audit_log_retention_days
    # (if set), and roll yesterday's per-company counts into
    # CompanySnapshot for the Dashboard trend chart.
    "purge-old-events": {
        "task": "app.tasks.jobs.purge_old_events",
        "schedule": crontab(hour=2, minute=0),
    },
    "purge-old-audit-log-entries": {
        "task": "app.tasks.jobs.purge_old_audit_log_entries",
        "schedule": crontab(hour=2, minute=5),
    },
    "record-company-snapshots": {
        "task": "app.tasks.jobs.record_company_snapshots",
        "schedule": crontab(hour=0, minute=10),
    },
}


@worker_process_init.connect
def _init_worker_process(**kwargs: object) -> None:
    """Build a fresh engine/session factory inside each forked worker
    child, after the fork — see the module docstring. `poolclass=NullPool`
    (not the default `QueuePool`): each task body runs its own
    `asyncio.run(...)` with a brand-new event loop, and a real pool would
    hand a later task a connection opened on an earlier, by-then-closed
    loop (asyncpg then raises "attached to a different loop"). This only
    applies to the Celery worker's engine — the FastAPI web process keeps
    one long-lived event loop and a real pool."""
    from app.db import session as db_session

    db_session.engine = create_async_engine(settings.database_url, poolclass=NullPool, echo=False)
    db_session.AsyncSessionLocal = async_sessionmaker(
        bind=db_session.engine, expire_on_commit=False, autoflush=False
    )
