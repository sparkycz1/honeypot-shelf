"""Regression guard for `app.tasks.celery_app`'s `beat_schedule` and
`include` list.

Every periodic sweep this app relies on (reachability/facts/packages/
services/readiness/update-checks/monitoring/OpenCanary-log-polling, the
per-minute Scheduling tick, and every retention purge) must actually be
registered here — `tests/conftest.py` monkeypatches `Task.apply_async`
itself for the whole suite, so no other test ever touches a real Celery
Beat/worker/broker pair and would ever notice a missing entry or an
unregistered task name. See `app.tasks.celery_app`'s own comments for the
gap this was written to catch.
"""

from __future__ import annotations

import app.main  # noqa: F401 - importing the whole app registers every task module
from app.scheduling.jobs import run_due_scheduled_tasks, run_scheduled_task
from app.tasks.celery_app import celery_app

_EXPECTED_SCHEDULE_TASKS = {
    "ping-all-honeypots": "app.tasks.jobs.ping_all_honeypots",
    "refresh-all-honeypot-facts": "app.tasks.jobs.refresh_all_honeypot_facts",
    "refresh-all-honeypot-packages": "app.tasks.jobs.refresh_all_honeypot_packages",
    "refresh-all-honeypot-services": "app.tasks.jobs.refresh_all_honeypot_services",
    "refresh-all-honeypot-readiness": "app.tasks.jobs.refresh_all_honeypot_readiness",
    "check-all-honeypot-updates": "app.tasks.jobs.check_all_honeypot_updates",
    "monitor-all-honeypots": "app.tasks.jobs.monitor_all_honeypots",
    "poll-all-honeypot-canary-logs": "app.tasks.jobs.poll_all_honeypot_canary_logs",
    "refresh-geoip-database": "app.tasks.jobs.refresh_geoip_database",
    "run-due-scheduled-tasks": "app.scheduling.jobs.run_due_scheduled_tasks",
    "purge-old-events": "app.tasks.jobs.purge_old_events",
    "purge-old-audit-log-entries": "app.tasks.jobs.purge_old_audit_log_entries",
    "purge-old-monitoring-samples": "app.tasks.jobs.purge_old_monitoring_samples",
    "purge-old-honeypot-update-runs": "app.tasks.jobs.purge_old_honeypot_update_runs",
    "purge-old-notification-logs": "app.tasks.jobs.purge_old_notification_logs",
    "record-company-snapshots": "app.tasks.jobs.record_company_snapshots",
    "purge-old-company-snapshots": "app.tasks.jobs.purge_old_company_snapshots",
}


def test_every_expected_sweep_is_in_the_beat_schedule():
    for entry_name, task_name in _EXPECTED_SCHEDULE_TASKS.items():
        entry = celery_app.conf.beat_schedule.get(entry_name)
        assert entry is not None, f"beat_schedule is missing {entry_name!r}"
        assert entry["task"] == task_name


def test_every_scheduled_task_name_is_actually_registered():
    """A `beat_schedule` entry pointing at a task name that was never
    `@celery_app.task`-decorated (or decorated in a module `include` never
    imports) fires forever without ever doing anything — Celery just NACKs
    the unregistered message, with nothing surfaced anywhere a human would
    see it."""
    registered = set(celery_app.tasks.keys())
    for task_name in _EXPECTED_SCHEDULE_TASKS.values():
        assert task_name in registered, f"{task_name!r} is not a registered Celery task"


def test_scheduling_jobs_module_is_in_the_worker_include_list():
    """Without this, a standalone `worker`/`beat` process (which only
    imports what `include=[...]` lists, see docker-compose.yml) never
    imports `app.scheduling.jobs` at all, so `run_scheduled_task` — the
    task an operator's "Run now" button actually enqueues — was never
    registered there either."""
    assert "app.scheduling.jobs" in celery_app.conf.include
    registered = set(celery_app.tasks.keys())
    assert run_due_scheduled_tasks.name in registered
    assert run_scheduled_task.name in registered
