"""Shared logic for triggering an action against a batch of honeypots.

Extracted out of the companies routes so the exact same code path is
used whether the trigger comes from a human clicking a button (per-honeypot,
per-company, or "All honeypots") or from `app.scheduling` firing a cron-like
scheduled task.

These take no queue handle of any kind — Celery task objects are just
importable Python objects, so enqueueing is a plain `some_task.delay(...)`
call. That is why this module works unchanged from inside an HTTP request
handler and from inside a background task.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_update_run import HoneypotUpdateRun, UpgradeStrategy
from app.ssh.power import PowerAction
from app.tasks.jobs import (
    check_honeypot_updates,
    poll_honeypot_canary_log,
    run_honeypot_update,
    run_remote_ssh_command,
    sample_honeypot_monitoring,
    send_honeypot_power_command,
)


async def trigger_updates(
    db: AsyncSession, honeypots: list[Honeypot], strategy: UpgradeStrategy
) -> tuple[uuid.UUID, int]:
    """Create one `HoneypotUpdateRun` per eligible honeypot (must have a pinned
    host key) under a shared batch id, commit, then enqueue a task for each.
    Returns (batch_id, skipped_count)."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    batch_id = uuid.uuid4()
    runs = [
        HoneypotUpdateRun(honeypot_id=m.id, strategy=strategy, batch_id=batch_id) for m in eligible
    ]
    db.add_all(runs)
    await db.commit()

    # Enqueue only after commit — the worker (a separate process) must be
    # able to find the row the moment it picks the task up.
    for run in runs:
        run_honeypot_update.delay(str(run.id))

    return batch_id, len(honeypots) - len(eligible)


async def trigger_check_updates(honeypots: list[Honeypot]) -> int:
    """Enqueue a `check_honeypot_updates` task for every eligible (pinned)
    honeypot. No batch tracking — unlike an actual update run, there's
    nothing meaningful to show on a results page; counts land on each
    honeypot's own record as each check finishes. Returns skipped count."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    for honeypot in eligible:
        check_honeypot_updates.delay(str(honeypot.id))
    return len(honeypots) - len(eligible)


async def send_power_to_honeypots(honeypots: list[Honeypot], action: PowerAction) -> int:
    """Enqueue a `send_honeypot_power_command` task for every eligible
    (pinned) honeypot. Returns skipped count."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    for honeypot in eligible:
        send_honeypot_power_command.delay(str(honeypot.id), action.value)
    return len(honeypots) - len(eligible)


async def trigger_canary_log_poll(honeypots: list[Honeypot]) -> int:
    """Enqueue a `poll_honeypot_canary_log` task for every eligible
    (pinned) honeypot — forces an immediate OpenCanary-log read instead of
    waiting for the next `OPENCANARY_LOG_POLL_INTERVAL_SECONDS` tick, e.g.
    for on-demand remote debugging via Scheduling's "run now". Returns
    skipped count."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    for honeypot in eligible:
        poll_honeypot_canary_log.delay(str(honeypot.id))
    return len(honeypots) - len(eligible)


async def trigger_monitoring_sample(honeypots: list[Honeypot]) -> int:
    """Enqueue a `sample_honeypot_monitoring` task for every eligible
    (pinned) honeypot — forces an immediate CPU/RAM/disk sample instead of
    waiting for the next `MONITORING_INTERVAL_SECONDS` tick. Returns
    skipped count."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    for honeypot in eligible:
        sample_honeypot_monitoring.delay(str(honeypot.id))
    return len(honeypots) - len(eligible)


async def run_custom_command_on_honeypots(honeypots: list[Honeypot], command: str) -> int:
    """Enqueue a `run_remote_ssh_command` task for every eligible (pinned)
    honeypot — the same task the interactive terminal's "run once and log"
    form uses. There's no result page here (unlike an update run): each
    task's outcome only lands in that task's own Celery result backend
    entry, same "fire and don't track" shape as
    `trigger_check_updates`/`send_power_to_honeypots`. Returns skipped
    count. **Callers must independently require write access** (and, for
    a scheduled task, company scoping) before calling this — this function
    itself performs no authorization, same trust boundary
    `run_remote_ssh_command` itself documents."""
    eligible = [m for m in honeypots if m.host_key_fingerprint]
    for honeypot in eligible:
        run_remote_ssh_command.delay(str(honeypot.id), command)
    return len(honeypots) - len(eligible)
