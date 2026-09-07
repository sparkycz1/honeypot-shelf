"""Registry of actions that can be attached to a scheduled task.

This is the extension point: adding a new schedulable action for some new
feature means writing one `run` function and calling `register_action()`
once (see `app.scheduling.builtin_actions` for the four that exist today) —
nothing about the schedule model, the scheduler tick, or the "New scheduled
task" form needs to change.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.honeypot import Honeypot


@dataclass(frozen=True)
class ActionRunResult:
    """What happened when a scheduled task fired, for `last_run_summary`."""

    attempted: int
    skipped: int


@dataclass(frozen=True)
class ScheduledActionParam:
    """One configurable option for an action, rendered in the scheduling
    form as either a `<select>` (`param_type="select"`, e.g. upgrade
    strategy for `system_update`) or a free-text `<input>`
    (`param_type="text"`, e.g. the command string for `run_command`).
    `choices` is only meaningful (and required) for `"select"`."""

    key: str
    label: str
    default: str
    param_type: Literal["select", "text"] = "select"
    choices: list[tuple[str, str]] = field(default_factory=list)  # (value, display label)
    placeholder: str = ""


# (db session, target honeypots, the action's stored params) -> what happened.
# No queue handle is threaded through: an action enqueues Celery tasks by
# importing and calling them (see `app.services.honeypot_actions`).
ActionRunFunc = Callable[[AsyncSession, list[Honeypot], dict[str, str]], Awaitable[ActionRunResult]]


@dataclass(frozen=True)
class ScheduledActionSpec:
    key: str
    label: str
    description: str
    run: ActionRunFunc
    params: list[ScheduledActionParam] = field(default_factory=list)
    # Shown as a caution in the schedule form for actions with no undo.
    destructive: bool = False


_REGISTRY: dict[str, ScheduledActionSpec] = {}


def register_action(spec: ScheduledActionSpec) -> None:
    if spec.key in _REGISTRY:
        raise ValueError(f'A schedulable action "{spec.key}" is already registered.')
    _REGISTRY[spec.key] = spec


def get_action(key: str) -> ScheduledActionSpec | None:
    return _REGISTRY.get(key)


def all_actions() -> list[ScheduledActionSpec]:
    return list(_REGISTRY.values())
