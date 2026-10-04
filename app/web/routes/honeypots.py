"""Managed honeypots (`/honeypots`) — the router the app mounts.

The routes themselves live in one module per area, each with its own
`APIRouter`, included here in a fixed order (same layout as debcontrol's
`machines_*` modules):

- `honeypots_list` — the list, saved views, adding and importing
  honeypots, configuration export/import, the package search and the bulk
  actions (every fixed path).
- `honeypots_detail` — one honeypot: Overview, editing, onboarding, host
  key, facts and packages, power, delete, acknowledging a problem.
- `honeypots_updates` — the Updates tab: check, preview, run, roll back,
  run history.
- `honeypots_monitoring` — the Monitoring tab and its "Refresh now".
- `honeypots_activity` — the Activity tab, its export and "Refresh now".
- `honeypots_logs` — the Logs tab and the Terminal page.
- `honeypots_config` — the Config tab: OpenCanary modules and the
  read-only root switch.

`honeypots_common` holds what they share."""

from __future__ import annotations

from fastapi import APIRouter

from app.web.routes import (
    honeypots_activity,
    honeypots_config,
    honeypots_detail,
    honeypots_list,
    honeypots_logs,
    honeypots_monitoring,
    honeypots_updates,
)

router = APIRouter()
# Order matters: a fixed path (`/new`, `/bulk/...`) has to be registered
# before a `/{id}/...` path that would otherwise swallow it.
router.include_router(honeypots_list.router)
router.include_router(honeypots_detail.router)
router.include_router(honeypots_updates.router)
router.include_router(honeypots_monitoring.router)
router.include_router(honeypots_activity.router)
router.include_router(honeypots_logs.router)
router.include_router(honeypots_config.router)
