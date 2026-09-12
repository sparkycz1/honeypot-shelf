"""Celery application: the app's one and only background task queue.

Run (both handled by docker-compose.yml — the `worker` and `beat` services):

    celery -A app.tasks.celery_app worker --loglevel=info --concurrency=4
    celery -A app.tasks.celery_app beat   --loglevel=info

Broker *and* result backend are the same Redis instance the rest of the app
already uses (`REDIS_URL`). Event ingestion itself is one of the periodic
sweeps here too, not a web-process write — `poll_all_honeypot_canary_logs`
SSH-polls each honeypot's own OpenCanary log on `OPENCANARY_LOG_POLL_
INTERVAL_SECONDS` and writes any new alert as a `HoneypotEvent` — see
`app.services.honeypot_events`.

See `app.db.session`'s module docstring and the fork-safety handler below
for why the DB engine is rebuilt in every worker child — same reasoning
and same fix as debcontrol's `app/tasks/celery_app.py`, copied verbatim:
Celery's prefork pool means naively importing `app.db.session` at module
load time would leave every forked worker child sharing the parent's
asyncpg connection pool, which fails in ways invisible to the (SQLite-based)
test suite and only bites a real Postgres deployment.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import timedelta

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import app.db.models  # noqa: F401 - registers every model before _bootstrap_interval_settings
from app.core.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)

settings = get_settings()
configure_logging(settings.log_level)

# Built-in fallback for the four interval settings below — used whenever
# `_bootstrap_interval_settings` can't read `AppSettings` yet (any process
# that isn't `celery ... beat` itself, or a `beat` process starting up
# before `alembic upgrade head` has run against a brand new Postgres).
# Matches `AppSettings`'s own column defaults (app/db/models/app_settings.py).
# Ported from an identical debcontrol change.
_INTERVAL_SETTING_DEFAULTS: dict[str, int] = {
    "reachability_check_interval_seconds": 60,
    "facts_refresh_interval_seconds": 600,
    "monitoring_interval_seconds": 120,
    "opencanary_log_poll_interval_seconds": 120,
}


def _bootstrap_interval_settings() -> dict[str, int]:
    """One-time, synchronous-from-the-caller's-perspective read of the four
    Beat-schedule intervals from `AppSettings`, for the `beat_schedule`
    dict literal below — a Celery schedule has to be a plain value computed
    once at import time, not something re-read from the database on every
    tick, so this is the one place these settings are still read "once at
    process start, restart to pick up a change," same as when they were
    environment variables.

    This module is imported identically by the web app, every Celery
    worker, and Celery Beat (see `app.tasks.jobs`'s import of `celery_app`)
    — but only Beat's own schedule actually depends on these four values,
    so only the `celery ... beat` process pays for the database round trip
    this needs; every other import (the web app, a worker, `alembic`, the
    test suite collecting `app.main`) gets the built-in defaults
    immediately with no I/O at all, matching this app's "tests never touch
    a real Postgres" contract. Detected via `sys.argv` rather than a
    dedicated environment variable, since that's already exactly how
    Celery itself is told which role to run as.

    Uses its own throwaway engine (`NullPool`, torn down again immediately)
    rather than `app.db.session`'s module-level one: this runs via
    `asyncio.run()` in the *parent* process before any worker child forks
    (see `_init_worker_process`'s own docstring for why a pooled connection
    and `asyncio.run()`'s own fresh event loop each call don't mix), and
    before that module's own engine may even be usable here.

    Falls back to `_INTERVAL_SETTING_DEFAULTS` — never raises — if the
    database isn't reachable yet, so a fresh, not-yet-migrated instance's
    `beat` container still starts instead of crash-looping; the real
    configured values take effect on the next restart once the database is
    up.

    Ported from an identical debcontrol change.

    **Real bug this module's own top-level `import app.db.models` guards
    against**: this function's DB query (via `get_or_create_app_settings`)
    is the very first ORM query this process ever runs, at *module import
    time* — before Celery's own `include=[...]` has had a chance to import
    `app.tasks.jobs` (where most model modules actually get imported as a
    side effect). SQLAlchemy configures every mapped class's relationships
    the first time *any* one of them is queried, and a `Mapped[list[Foo]]`
    relationship using a plain string/forward-reference annotation (every
    relationship in this codebase, since `from __future__ import
    annotations` is in effect everywhere) needs `Foo` to already be
    registered in the shared declarative registry at that moment — not
    merely imported eventually. Confirmed live: on its very first boot
    after `HoneypotNotificationSubscription` was added (`User.
    notification_subscriptions` referencing it), this function's own
    `except Exception` above caught a `sqlalchemy.exc.InvalidRequestError:
    ... failed to locate a name 'HoneypotNotificationSubscription'` here —
    not a crash (the `except` did its job, `beat` started fine on the
    hardcoded fallback defaults), but a real, avoidable miss: the actual
    configured interval values silently didn't take effect until the next
    restart, logged as a scary-looking traceback each time. The top-level
    `import app.db.models` (the same whole-registry import
    `alembic/env.py` already relies on for autogenerate, per that
    package's own docstring) guarantees every model is registered before
    this function's query can trigger mapper configuration, so the real
    values are read on the very first boot instead.
    """
    if "beat" not in sys.argv:
        return dict(_INTERVAL_SETTING_DEFAULTS)

    async def _fetch() -> dict[str, int]:
        from app.core.app_settings import get_or_create_app_settings

        engine = create_async_engine(settings.database_url, poolclass=NullPool, echo=False)
        try:
            session_factory = async_sessionmaker(
                bind=engine, expire_on_commit=False, autoflush=False
            )
            async with session_factory() as db:
                app_settings = await get_or_create_app_settings(db)
                return {key: getattr(app_settings, key) for key in _INTERVAL_SETTING_DEFAULTS}
        finally:
            await engine.dispose()

    try:
        return asyncio.run(_fetch())
    except Exception:
        logger.warning(
            "Could not read background-check intervals from the database at startup "
            "(using the built-in defaults until the next restart) — is the database "
            "reachable and migrated yet?",
            exc_info=True,
        )
        return dict(_INTERVAL_SETTING_DEFAULTS)

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

_interval_settings = _bootstrap_interval_settings()
celery_app.conf.beat_schedule = {
    # --- Fleet sweeps — each one only *enqueues* one task per due honeypot
    # (see each `_due_honeypots` caller in app/tasks/jobs.py); the actual
    # SSH round trips run on `worker`, fanned out. `timedelta`, not
    # `crontab`: these cadences are now DB-backed (`AppSettings` — Settings
    # → Checks & retention), and Beat only re-reads them at its own
    # startup, same "restart to pick up a change" contract they had as
    # `.env` vars — see `_bootstrap_interval_settings` above and
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
        "schedule": timedelta(seconds=_interval_settings["reachability_check_interval_seconds"]),
    },
    "refresh-all-honeypot-facts": {
        "task": "app.tasks.jobs.refresh_all_honeypot_facts",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "refresh-all-honeypot-packages": {
        "task": "app.tasks.jobs.refresh_all_honeypot_packages",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "refresh-all-honeypot-services": {
        "task": "app.tasks.jobs.refresh_all_honeypot_services",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "refresh-all-honeypot-readiness": {
        "task": "app.tasks.jobs.refresh_all_honeypot_readiness",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "check-all-honeypot-updates": {
        "task": "app.tasks.jobs.check_all_honeypot_updates",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "monitor-all-honeypots": {
        "task": "app.tasks.jobs.monitor_all_honeypots",
        "schedule": timedelta(seconds=_interval_settings["monitoring_interval_seconds"]),
    },
    "poll-all-honeypot-canary-logs": {
        "task": "app.tasks.jobs.poll_all_honeypot_canary_logs",
        "schedule": timedelta(
            seconds=_interval_settings["opencanary_log_poll_interval_seconds"]
        ),
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
