"""Something-changed-go-check push notifications over Redis pub/sub —
what makes a honeypot's Overview/Monitoring/Updates tabs (and, more
broadly, the Dashboard, Map, Audit log, Companies list, and a user's own
Notification history) update the moment something relevant happens,
instead of waiting out their htmx polling interval (see
`app/web/routes/live_ws.py`, the WebSocket that relays these to the
browser, and `app/web/static/js/live-updates.js`, the client that turns
one into an htmx re-fetch of the matching panel).

Deliberately minimal: a published message carries only a `kind` — never
honeypot/audit/notification data. A client that receives one just
re-triggers the matching htmx panel's own `hx-get` (still permission/
scope-checked exactly like its periodic poll already was); every channel
here is a doorbell, not a data feed, so there's nothing sensitive in any
of them and no risk of a push payload drifting out of sync with what a
fresh fetch would show.

Four channel shapes, all sharing the same best-effort publish/relay
machinery:
- **Per-honeypot** (`channel_for`/`publish_honeypot_event`) — the
  original one, for a single honeypot's own tabs.
- **Fleet-wide** (`FLEET_CHANNEL`/`publish_fleet_event`) — "some
  honeypot's reachability or activity changed", fired alongside the
  per-honeypot publish for `KIND_STATUS`/`KIND_ACTIVITY` specifically
  (the only two kinds a cross-honeypot view like the Dashboard or Map
  actually cares about). Every logged-in user may subscribe — the
  payload carries no company/honeypot identity, so there's nothing to
  scope; the panel it triggers a re-fetch of is scoped on its own.
- **Admin-wide** (`ADMIN_CHANNEL`/`publish_admin_event`) — "a new audit
  log entry was written", fired from `app.audit.log_event` itself, so
  it also covers company/user create-edit-delete (always audit-logged).
  Superadmin-only subscription, matching the Audit log/Companies/Users
  pages this feeds.
- **Per-user notifications** (`notifications_channel_for`/
  `publish_notifications_event`) — "a NotificationLog row was just
  written for this user", fired from `app.services.notifications._log`.

Called from two different worlds: the FastAPI process (which has a
long-lived `app.state.redis`) and Celery worker processes (separate OS
processes entirely, each running these jobs' `asyncio.run(...)` wrapper —
see `app.tasks.jobs`'s module docstring). Rather than plumb `app.state`
through to worker code that has no `app` object, this opens its own
short-lived Redis connection per publish. That's more round trips than
reusing a shared connection, but publishes happen at most a few times per
job (not per SSH byte), and it keeps this module usable from anywhere
without a FastAPI request/app in scope.
"""

from __future__ import annotations

import json
import logging

import redis.asyncio as aioredis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_CHANNEL_PREFIX = "debcontrol:live:honeypot:"
FLEET_CHANNEL = "debcontrol:live:fleet"
ADMIN_CHANNEL = "debcontrol:live:admin"
_NOTIFICATIONS_CHANNEL_PREFIX = "debcontrol:live:notifications:"

# The finite set of "something changed" hints a client understands — see
# app/web/static/js/live-updates.js. Keeping this closed (rather than any
# free-form string) means a typo here fails loudly in review, not silently
# as a push nothing on the client ever matches.
Kind = str
KIND_STATUS = "status"
KIND_FACTS = "facts"
KIND_PACKAGES = "packages"
KIND_SERVICES = "services"
KIND_UPDATES = "updates"
KIND_MONITORING = "monitoring"
KIND_ACTIVITY = "activity"
KIND_AUDIT = "audit"
KIND_NOTIFICATION = "notification"


def channel_for(honeypot_id: str) -> str:
    return f"{_CHANNEL_PREFIX}{honeypot_id}"


def notifications_channel_for(user_id: str) -> str:
    return f"{_NOTIFICATIONS_CHANNEL_PREFIX}{user_id}"


async def _publish(channel: str, kind: Kind) -> None:
    """Best-effort — a failed publish just means the affected panel waits
    for its own polling fallback to catch up a little later. Never worth
    failing (or even slowing down) the actual job/request over, so every
    error is caught and logged, not raised."""
    try:
        client: aioredis.Redis = aioredis.from_url(  # type: ignore[no-untyped-call]
            get_settings().redis_url
        )
        try:
            await client.publish(channel, json.dumps({"kind": kind}))
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001 - best-effort, see docstring
        logger.warning("live_updates: failed to publish %r on %s", kind, channel)


async def publish_honeypot_event(honeypot_id: str, kind: Kind) -> None:
    await _publish(channel_for(honeypot_id), kind)


async def publish_fleet_event(kind: Kind) -> None:
    await _publish(FLEET_CHANNEL, kind)


async def publish_admin_event(kind: Kind = KIND_AUDIT) -> None:
    await _publish(ADMIN_CHANNEL, kind)


async def publish_notifications_event(user_id: str, kind: Kind = KIND_NOTIFICATION) -> None:
    await _publish(notifications_channel_for(user_id), kind)
