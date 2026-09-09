"""Registers the schedulable actions that exist today.

`register_builtin_actions()` is called from `app.main` at import time (so the
web UI's "New scheduled task" form has something to list), from
`app.scheduling.jobs` at import time, and again from each forked Celery
worker child (`app.tasks.celery_app`'s `worker_process_init` handler, so a
child that inherited an empty registry still has one) — it's idempotent, so
calling it from all three is harmless.

To make a new feature schedulable: write an `ActionRunFunc` (reusing
`app.services.honeypot_actions` where it fits) and add one
`register_action(ScheduledActionSpec(...))` call below. That's the whole
integration surface — the schedule form, validation, and the scheduler tick
all read from the registry, not from a hardcoded list of actions.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_update_run import UpgradeStrategy
from app.scheduling.actions import (
    ActionRunResult,
    ScheduledActionParam,
    ScheduledActionSpec,
    get_action,
    register_action,
)
from app.services.honeypot_actions import (
    run_custom_command_on_honeypots,
    send_power_to_honeypots,
    trigger_canary_log_poll,
    trigger_check_updates,
    trigger_monitoring_sample,
    trigger_updates,
)
from app.ssh.power import PowerAction


async def _run_system_update(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    strategy = UpgradeStrategy(params.get("strategy") or UpgradeStrategy.DIST_UPGRADE.value)
    _batch_id, skipped = await trigger_updates(db, honeypots, strategy)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_check_updates(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_check_updates(honeypots)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_reboot(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    skipped = await send_power_to_honeypots(honeypots, PowerAction.REBOOT)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_shutdown(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    skipped = await send_power_to_honeypots(honeypots, PowerAction.SHUTDOWN)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_custom_command(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    command = params.get("command", "").strip()
    if not command:
        return ActionRunResult(attempted=0, skipped=len(honeypots))
    skipped = await run_custom_command_on_honeypots(honeypots, command)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_canary_log_poll(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_canary_log_poll(honeypots)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


async def _run_monitoring_sample(
    db: AsyncSession, honeypots: list[Honeypot], params: dict[str, str]
) -> ActionRunResult:
    skipped = await trigger_monitoring_sample(honeypots)
    return ActionRunResult(attempted=len(honeypots) - skipped, skipped=skipped)


def register_builtin_actions() -> None:
    if get_action("system_update") is not None:
        return  # already registered — safe to call from multiple entry points

    register_action(
        ScheduledActionSpec(
            key="system_update",
            label="System update",
            description=(
                "apt-get update, then dist-upgrade or full-upgrade, then "
                "autoremove/autoclean — same as the manual System updates panel."
            ),
            params=[
                ScheduledActionParam(
                    key="strategy",
                    label="Upgrade strategy",
                    choices=[
                        (UpgradeStrategy.DIST_UPGRADE.value, "dist-upgrade"),
                        (UpgradeStrategy.FULL_UPGRADE.value, "full-upgrade"),
                    ],
                    default=UpgradeStrategy.DIST_UPGRADE.value,
                )
            ],
            run=_run_system_update,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="check_updates",
            label="Check for updates",
            description="Dry run — counts available updates without installing anything.",
            run=_run_check_updates,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="reboot",
            label="Reboot",
            description="Sends `shutdown -r now` to every targeted honeypot.",
            run=_run_reboot,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="shutdown",
            label="Shut down",
            description=(
                "Sends `shutdown -h now`. The honeypot stays off until someone "
                "powers it back on — there's no scheduled \"power on\"."
            ),
            run=_run_shutdown,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="run_command",
            label="Run command",
            description=(
                "Runs a shell command on each targeted honeypot, as that honeypot's "
                "own configured SSH user — the account needs whatever permission "
                "the command itself requires (e.g. its own sudo rule for a "
                "privileged command); nothing extra is granted for this."
            ),
            params=[
                ScheduledActionParam(
                    key="command",
                    label="Command",
                    default="",
                    param_type="text",
                    placeholder="apt-get clean",
                )
            ],
            run=_run_custom_command,
            destructive=True,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="poll_canary_log",
            label="Force OpenCanary log poll now",
            description=(
                "Reads whatever's new in OpenCanary's own log immediately, instead of "
                "waiting for the next OPENCANARY_LOG_POLL_INTERVAL_SECONDS tick — same "
                "read the Activity tab's automatic sweep does. Useful for on-demand "
                "remote debugging."
            ),
            run=_run_canary_log_poll,
        )
    )
    register_action(
        ScheduledActionSpec(
            key="sample_monitoring",
            label="Force monitoring sample now",
            description=(
                "Takes a CPU/RAM/disk-I/O/failed-services sample immediately, instead "
                "of waiting for the next MONITORING_INTERVAL_SECONDS tick — same sample "
                "the Monitoring tab's automatic sweep takes. Useful for on-demand "
                "remote debugging."
            ),
            run=_run_monitoring_sample,
        )
    )
