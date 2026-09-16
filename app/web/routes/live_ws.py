"""WebSocket relay for "something changed" push notifications
(`app/services/live_updates.py`) — what lets htmx panels across the app
refresh the moment something relevant happens instead of waiting out
their own polling interval. See `app/web/static/js/live-updates.js` for
the browser side.

Four routes, one shared relay loop (`_serve`) underneath — they differ
only in how they authenticate/scope the connection and which Redis
channel they subscribe to:
- `/honeypots/{id}/live/ws` — one honeypot's own tabs (Overview,
  Monitoring, Activity, Updates).
- `/live/fleet/ws` — any logged-in user, the fleet-wide channel (Dashboard,
  Map).
- `/live/admin/ws` — superadmin only, the admin channel (Audit log,
  Companies list).
- `/live/notifications/ws` — any logged-in user, their own
  per-user notifications channel (Notification history).

Auth follows the exact same pattern `app/web/routes/terminal_ws.py`
documents in its own module docstring, for the same reason:
`app.auth.middleware` never runs for WebSocket requests, so each route
re-implements a session-cookie check by hand (no write check needed —
unlike the terminal, every one of these sockets only ever emits a `kind`
string telling the client which already-scope-checked htmx panel to
re-fetch, never any actual data, so a connection learns nothing beyond
"something, somewhere in view, changed").

**Protocol**: text frames only, each `{"kind": "..."}` — see
`live_updates.py`'s `Kind` constants. One-way (server to client);
anything the client sends is ignored. No DB/SSH access happens once a
connection is established — this is pure Redis pub/sub relay, so a slow
or stuck honeypot (or a slow Postgres query) can never block any of
these sockets.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

from fastapi import APIRouter, WebSocket, status
from redis.asyncio.client import PubSub

from app.auth.scope import can_see_honeypot
from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.db.models.honeypot import Honeypot
from app.db.models.user import User
from app.services.live_updates import ADMIN_CHANNEL, FLEET_CHANNEL, channel_for
from app.services.live_updates import notifications_channel_for as _notifications_channel_for

router = APIRouter()

_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION

# Idle sockets are cheap (pure Redis pub/sub, nothing per-connection) but
# not free — a hard cap means an abandoned browser tab doesn't hold one
# open forever. A viewer with the tab still open just reconnects (see
# live-updates.js's retry loop), invisibly.
_SESSION_MAX_SECONDS = 6 * 60 * 60  # 6 hours


async def _authenticated_user(websocket: WebSocket) -> User | None:
    """Returns the logged-in user for this connection, or `None` after
    already closing the socket with an explanatory reason. Shared first
    step for every route below — each then applies its own extra scope
    check (a honeypot lookup, or `is_superadmin`) on top."""
    raw_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        session = await get_valid_session(db, raw_token)
        if session is None:
            await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
            return None
        return session.user


async def _authenticate_honeypot(websocket: WebSocket, honeypot_id: uuid.UUID) -> Honeypot | None:
    raw_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        session = await get_valid_session(db, raw_token)
        if session is None:
            await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
            return None
        user = session.user
        honeypot: Honeypot | None = await db.get(Honeypot, honeypot_id)
        if honeypot is None or not can_see_honeypot(user, honeypot):
            await websocket.close(code=_POLICY_VIOLATION, reason="Honeypot not found.")
            return None
    return honeypot


@router.websocket("/honeypots/{honeypot_id}/live/ws")
async def honeypot_live_websocket(websocket: WebSocket, honeypot_id: uuid.UUID) -> None:
    honeypot = await _authenticate_honeypot(websocket, honeypot_id)
    if honeypot is None:
        return
    await _serve(websocket, channel_for(str(honeypot.id)))


@router.websocket("/live/fleet/ws")
async def fleet_live_websocket(websocket: WebSocket) -> None:
    """Dashboard/Map: "some honeypot's reachability or activity changed
    somewhere" — see `app.services.live_updates`'s module docstring for
    why this needs no per-connection scoping."""
    user = await _authenticated_user(websocket)
    if user is None:
        return
    await _serve(websocket, FLEET_CHANNEL)


@router.websocket("/live/admin/ws")
async def admin_live_websocket(websocket: WebSocket) -> None:
    """Audit log/Companies list: "a new audit log entry was written"."""
    user = await _authenticated_user(websocket)
    if user is None:
        return
    if not user.is_superadmin:
        await websocket.close(code=_POLICY_VIOLATION, reason="Superadmin only.")
        return
    await _serve(websocket, ADMIN_CHANNEL)


@router.websocket("/live/notifications/ws")
async def notifications_live_websocket(websocket: WebSocket) -> None:
    """Notification history: "a send attempt was just logged for you"."""
    user = await _authenticated_user(websocket)
    if user is None:
        return
    await _serve(websocket, _notifications_channel_for(str(user.id)))


async def _serve(websocket: WebSocket, channel: str) -> None:
    """Shared relay loop: accept, subscribe to `channel`, forward every
    message verbatim until the client disconnects or `_SESSION_MAX_
    SECONDS` elapses, then clean up. Identical shape regardless of which
    route/channel called it."""
    await websocket.accept()

    redis = websocket.app.state.redis
    pubsub = redis.pubsub()
    await pubsub.subscribe(channel)
    try:
        listen_task = asyncio.ensure_future(_relay(websocket, pubsub))
        # Watching for the client closing its end is the only reason this
        # needs a second task at all — this socket never expects any
        # message from the client, only its disconnect.
        disconnect_task = asyncio.ensure_future(_watch_disconnect(websocket))
        timeout_task = asyncio.ensure_future(asyncio.sleep(_SESSION_MAX_SECONDS))
        try:
            await asyncio.wait(
                {listen_task, disconnect_task, timeout_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in (listen_task, disconnect_task, timeout_task):
                task.cancel()
            for task in (listen_task, disconnect_task, timeout_task):
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(channel)
        with contextlib.suppress(Exception):
            await pubsub.aclose()
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)


async def _relay(websocket: WebSocket, pubsub: PubSub) -> None:
    async for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        data = message.get("data")
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        if isinstance(data, str):
            await websocket.send_text(data)


async def _watch_disconnect(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
