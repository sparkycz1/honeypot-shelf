"""Celery tasks that evaluate and fire scheduled tasks.

`run_due_scheduled_tasks` runs on a fixed one-minute Celery Beat entry
(`crontab()`, see `app.tasks.celery_app`) — cron expressions are
minute-grained anyway, so a fixed per-minute tick is simpler than a
configurable interval and needs no new setting. It only enqueues; it never
runs an action inline, for the same reason every other fan-out job in this
app doesn't — one very large group could otherwise make the tick itself run
long.

Same two-part shape as `app.tasks.jobs`: an `async def _...` doing the real
work, plus a one-line synchronous `@celery_app.task` wrapper around
`asyncio.run(...)`.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.audit import log_event
from app.db import session as db_session
from app.db.models.audit_log import AuditOutcome
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun, ScheduledTaskRunOutcome
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.scheduling.cron import compute_next_run
from app.scheduling.targets import resolve_target_honeypots
from app.tasks.celery_app import celery_app

# `actor` for every audit entry this module writes — there's no HTTP
# request (and so no IP) behind a schedule firing on its own; this label is
# what distinguishes "the scheduler did this" from a human's IP address in
# the audit log.
_SCHEDULER_ACTOR = "scheduler (automatic)"

logger = logging.getLogger(__name__)

# Registering here too (as well as in app.main) covers running just the
# worker/beat process without ever importing app.main.
register_builtin_actions()


async def _run_due_scheduled_tasks() -> None:
    """Every enabled task whose `next_run_at` has passed gets a
    `run_scheduled_task` task enqueued, and its `next_run_at` is advanced
    immediately (before the task actually runs) — so a slow-running action
    can't cause this same task to be re-enqueued on the next tick before it
    has even started."""
    now = datetime.now(UTC)

    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScheduledTask).where(
                ScheduledTask.is_enabled, ScheduledTask.next_run_at <= now
            )
        )
        due = list(result.scalars().all())
        if not due:
            return

        for task in due:
            run_scheduled_task.delay(str(task.id))
            try:
                task.next_run_at = compute_next_run(task.cron_expression, now)
            except ValueError:
                # Shouldn't happen — expressions are validated on save — but
                # don't let a bad stored expression wedge this task into
                # firing every minute forever if it ever does.
                logger.exception(
                    "Disabling scheduled task %s: invalid cron expression %r",
                    task.id,
                    task.cron_expression,
                )
                task.is_enabled = False

        await session.commit()


@celery_app.task(name="app.scheduling.jobs.run_due_scheduled_tasks")
def run_due_scheduled_tasks() -> None:
    asyncio.run(_run_due_scheduled_tasks())


async def _run_scheduled_task(task_id: str) -> dict[str, Any]:
    """Execute one scheduled task: resolve its current target honeypots and
    hand them to its action's `run` function (see `app.scheduling.actions`).
    Records only a short summary, not a full run log — the underlying
    action's own task (e.g. `HoneypotUpdateRun`) already records what
    actually happened on each honeypot."""
    async with db_session.AsyncSessionLocal() as session:
        task = await session.get(ScheduledTask, uuid.UUID(task_id))
        if task is None:
            return {"ok": False, "error": "Scheduled task not found."}

        action = get_action(task.action)
        if action is None:
            summary = f'Unknown action "{task.action}" — nothing was run.'
            task.last_run_at = datetime.now(UTC)
            task.last_run_summary = summary
            session.add(
                ScheduledTaskRun(
                    task_id=task.id,
                    outcome=ScheduledTaskRunOutcome.FAILURE,
                    summary=summary,
                    error=summary,
                )
            )
            await session.commit()
            logger.warning("run_scheduled_task(%s): %s", task.id, summary)
            await log_event(
                session,
                actor=_SCHEDULER_ACTOR,
                action="scheduled_task.fired",
                summary=f'Scheduled task "{task.name}" fired: {summary}',
                outcome=AuditOutcome.FAILURE,
                target_type="scheduled_task",
                target_id=task.id,
                target_label=task.name,
            )
            return {"ok": False, "error": summary}

        # Anything past this point (resolving targets, dispatching the
        # action's own underlying jobs) is wrapped so a failure here — a DB
        # hiccup, a bug in a third-party action — still leaves a row behind
        # to retry from, instead of silently vanishing into Celery's own
        # failure handling with no trace in this app.
        try:
            honeypots = await resolve_target_honeypots(session, task)
            result = await action.run(session, honeypots, task.action_params or {})
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            summary = f"Failed to run: {exc}"
            task.last_run_at = datetime.now(UTC)
            task.last_run_summary = summary
            session.add(
                ScheduledTaskRun(
                    task_id=task.id,
                    outcome=ScheduledTaskRunOutcome.FAILURE,
                    summary=summary,
                    error=str(exc),
                )
            )
            await session.commit()
            logger.exception("run_scheduled_task(%s) failed", task.id)
            await log_event(
                session,
                actor=_SCHEDULER_ACTOR,
                action="scheduled_task.fired",
                summary=f'Scheduled task "{task.name}" fired ({task.action}): {summary}',
                outcome=AuditOutcome.FAILURE,
                target_type="scheduled_task",
                target_id=task.id,
                target_label=task.name,
            )
            return {"ok": False, "error": summary}

        summary = f"Triggered for {result.attempted} honeypot(s)."
        if result.skipped:
            summary = (
                f"Triggered for {result.attempted} honeypot(s), "
                f"{result.skipped} skipped (no pinned host key)."
            )
        task.last_run_at = datetime.now(UTC)
        task.last_run_summary = summary
        session.add(
            ScheduledTaskRun(
                task_id=task.id,
                outcome=ScheduledTaskRunOutcome.SUCCESS,
                summary=summary,
                attempted=result.attempted,
                skipped=result.skipped,
            )
        )
        await session.commit()

        await log_event(
            session,
            actor=_SCHEDULER_ACTOR,
            action="scheduled_task.fired",
            summary=f'Scheduled task "{task.name}" fired ({task.action}): {summary}',
            target_type="scheduled_task",
            target_id=task.id,
            target_label=task.name,
            details={"attempted": result.attempted, "skipped": result.skipped},
        )

        return {"ok": True, "attempted": result.attempted, "skipped": result.skipped}


@celery_app.task(name="app.scheduling.jobs.run_scheduled_task")
def run_scheduled_task(task_id: str) -> dict[str, Any]:
    return asyncio.run(_run_scheduled_task(task_id))
