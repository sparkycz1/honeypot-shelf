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
from datetime import timedelta

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
    # Both modules' `@celery_app.task(...)`-decorated functions need to
    # actually run at import time to end up in *this* process's task
    # registry — `app.scheduling.jobs` (Scheduling's own tick +
    # run-scheduled-task) used to be missing here entirely. The web
    # process always imports it anyway (routes call `run_scheduled_task.
    # delay(...)` directly), but the standalone `worker`/`beat` processes
    # (`celery -A app.tasks.celery_app worker`/`beat`, see
    # docker-compose.yml) only ever import what's listed here — without
    # it, a worker receiving a `run_scheduled_task`/`run_due_scheduled_
    # tasks` message from the broker rejected it as an unregistered task,
    # silently (no exception surfaced anywhere a human would see it: the
    # message is just NACKed). Caught by the same kind of "not exercised
    # by the test suite" gap as the missing `beat_schedule` entries below —
    # `tests/conftest.py` monkeypatches `Task.apply_async` itself, so no
    # test ever touches a real broker/worker pair.
    include=["app.tasks.jobs", "app.scheduling.jobs"],
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
    # --- Fleet sweeps — each one only *enqueues* one task per due honeypot
    # (see each `_due_honeypots` caller in app/tasks/jobs.py); the actual
    # SSH round trips run on `worker`, fanned out. `timedelta`, not
    # `crontab`: these cadences are configurable via `.env`
    # (REACHABILITY_CHECK_INTERVAL_SECONDS etc.), and Beat only re-reads
    # them at its own startup — see this file's own module docstring and
    # docker-compose.yml's comment on the `beat` service.
    #
    # These nine entries (plus the per-minute Scheduling tick right below)
    # were missing entirely until this comment was added — `beat_schedule`
    # only ever had the three daily entries further down, so nothing here
    # actually fired on its own: no periodic reachability/facts/packages/
    # services/readiness/update-check/monitoring sweep, no honeypot
    # scheduled-task ever firing on its cron, and none of the retention
    # purges below except the events/audit-log ones. Every one of those
    # tasks still worked fine when triggered manually (a "Refresh now"
    # button, `.delay()` from a route) — only the *automatic* cadence was
    # dead. Not caught by the test suite: `tests/conftest.py` monkeypatches
    # `Task.apply_async` itself, so no test ever touches a real Beat/
    # worker/broker pair — see `tests/test_beat_schedule.py`, added
    # alongside this fix, for the regression guard.
    "ping-all-honeypots": {
        "task": "app.tasks.jobs.ping_all_honeypots",
        "schedule": timedelta(seconds=settings.reachability_check_interval_seconds),
    },
    "refresh-all-honeypot-facts": {
        "task": "app.tasks.jobs.refresh_all_honeypot_facts",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "refresh-all-honeypot-packages": {
        "task": "app.tasks.jobs.refresh_all_honeypot_packages",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "refresh-all-honeypot-services": {
        "task": "app.tasks.jobs.refresh_all_honeypot_services",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "refresh-all-honeypot-readiness": {
        "task": "app.tasks.jobs.refresh_all_honeypot_readiness",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "check-all-honeypot-updates": {
        "task": "app.tasks.jobs.check_all_honeypot_updates",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "monitor-all-honeypots": {
        "task": "app.tasks.jobs.monitor_all_honeypots",
        "schedule": timedelta(seconds=settings.monitoring_interval_seconds),
    },
    "poll-all-honeypot-canary-logs": {
        "task": "app.tasks.jobs.poll_all_honeypot_canary_logs",
        "schedule": timedelta(seconds=settings.opencanary_log_poll_interval_seconds),
    },
    # Cron expressions are minute-grained anyway, so a fixed per-minute
    # tick needs no new setting of its own — see
    # `app.scheduling.jobs`'s module docstring.
    "run-due-scheduled-tasks": {
        "task": "app.scheduling.jobs.run_due_scheduled_tasks",
        "schedule": crontab(),
    },
    # --- Once a day: purge honeypot_events older than EVENT_RETENTION_DAYS,
    # audit_log_entries older than AppSettings.audit_log_retention_days
    # (if set), monitoring/reachability samples and honeypot update runs
    # per their own retention settings, and roll yesterday's per-company
    # counts into CompanySnapshot for the Dashboard trend chart (then purge
    # *those* past their own retention, once they're old enough for it to
    # matter). Staggered a few minutes apart — same reasoning debcontrol's
    # own daily jobs are staggered — so two purges never contend for the
    # same tables' locks at once.
    "purge-old-events": {
        "task": "app.tasks.jobs.purge_old_events",
        "schedule": crontab(hour=2, minute=0),
    },
    "purge-old-audit-log-entries": {
        "task": "app.tasks.jobs.purge_old_audit_log_entries",
        "schedule": crontab(hour=2, minute=5),
    },
    "purge-old-monitoring-samples": {
        "task": "app.tasks.jobs.purge_old_monitoring_samples",
        "schedule": crontab(hour=2, minute=10),
    },
    "purge-old-honeypot-update-runs": {
        "task": "app.tasks.jobs.purge_old_honeypot_update_runs",
        "schedule": crontab(hour=2, minute=15),
    },
    "record-company-snapshots": {
        "task": "app.tasks.jobs.record_company_snapshots",
        "schedule": crontab(hour=0, minute=10),
    },
    "purge-old-company-snapshots": {
        "task": "app.tasks.jobs.purge_old_company_snapshots",
        "schedule": crontab(hour=2, minute=20),
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
