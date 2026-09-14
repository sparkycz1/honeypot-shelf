"""Plain JSON webhook delivery for Notifications — the other delivery
channel alongside `app.services.smtp`, for a
`HoneypotNotificationSubscription` with `delivery_channel=webhook`. Ported
from an identical debcontrol feature (a rule-level webhook channel there).

Deliberately as small as `app.services.smtp`: one POST, one fixed JSON
shape, no retry/signing/templating of its own — `app.services.
notifications` decides *when* to call this and what the payload means;
this module doesn't know what a "notification" is at all, just how to
hand a JSON body to a URL, the same split `send_email`/`app.services.
notifications` already has.

**SSRF guard**: unlike debcontrol (where a webhook URL is part of an
admin-authored `NotificationRule`, superadmin-only), this app's
Notifications are self-service — *any* logged-in user, regardless of
access level, can set a webhook URL on their own subscription (see
`app.web.routes.notifications`). Without a check, a low-privileged user
could point a webhook at an internal-only address (a cloud metadata
endpoint, another container on the compose network, localhost) and use
the `worker` container as an open network probe/relay. `_reject_unsafe_target`
resolves the hostname and rejects anything that isn't a public,
routable address — checked both when a subscription is saved (fail fast,
readable error) and again here at send time (defends against a DNS
answer changing between the two, a classic SSRF rebind).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 4096  # only ever read for the debug log, never surfaced further
_ALLOWED_SCHEMES = ("http", "https")


class UnsafeWebhookTargetError(ValueError):
    """Raised by `validate_webhook_url`/`send_webhook` when a URL's scheme
    or resolved address isn't safe to let this app's own containers
    connect to — see this module's docstring."""


def validate_webhook_url(url: str) -> None:
    """Raise `UnsafeWebhookTargetError` if `url` isn't a plausible,
    safe-to-send-to webhook target: http(s) only, a hostname present, and
    every address it currently resolves to is public/routable (not
    loopback, link-local, private, or otherwise reserved — see
    `ipaddress.ip_address`'s own `.is_*` properties). Called both from the
    Notifications save route (immediate, readable feedback) and again from
    `send_webhook` right before connecting (the address a hostname
    resolves to can change between the two)."""
    parsed = urlsplit(url)
    if parsed.scheme not in _ALLOWED_SCHEMES or not parsed.hostname:
        raise UnsafeWebhookTargetError("Webhook URL must be a plain http:// or https:// address.")
    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except OSError as exc:
        raise UnsafeWebhookTargetError(f"Couldn't resolve webhook host: {exc}") from exc
    if not addrinfo:
        raise UnsafeWebhookTargetError("Couldn't resolve webhook host.")
    for *_rest, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise UnsafeWebhookTargetError(
                "Webhook URL resolves to a non-public address, which this app "
                "refuses to send requests to."
            )


def send_webhook(url: str, payload: dict[str, Any]) -> None:
    """Synchronous POST of `payload` as JSON to `url` (stdlib `urllib`, no
    extra HTTP client dependency for this one feature) — always run this
    via `asyncio.to_thread` from an async caller, same seam
    `app.services.smtp.send_email` already crosses. Raises
    `UnsafeWebhookTargetError` (see `validate_webhook_url`) or on any
    non-2xx response/transport error; the caller (`app.services.
    notifications`) decides how to log/swallow either, same as an SMTP
    send failure."""
    validate_webhook_url(url)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - validated above, not raw user input
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "HoneypotShelf-Notifications/1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:  # noqa: S310
        response.read(_MAX_RESPONSE_BYTES)
        if not (200 <= response.status < 300):
            raise urllib.error.HTTPError(
                url, response.status, "non-2xx webhook response", response.headers, None
            )
