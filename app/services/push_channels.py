"""Push and team-chat notification channels: ntfy, Gotify, Telegram,
Discord, Pushover, Mattermost, Slack and Microsoft Teams — ported from
debcontrol. Each is a single HTTPS request with the rule's rendered
subject and body. What each channel needs, stored on the rule
(`NotificationRule`):

| channel    | `webhook_url`                        | token (encrypted)       | recipient      |
|------------|--------------------------------------|-------------------------|----------------|
| ntfy       | topic URL `https://ntfy.sh/mytopic`  | access token (optional) | —              |
| gotify     | server URL `https://gotify.example`  | application token       | —              |
| telegram   | —                                    | bot token               | chat id        |
| discord    | channel webhook URL                  | —                       | —              |
| pushover   | —                                    | application API token   | user/group key |
| mattermost | incoming webhook URL                 | —                       | —              |
| slack      | incoming webhook URL                 | —                       | —              |
| teams      | Workflows webhook URL                | —                       | —              |

Teams takes an Adaptive Card — the format Microsoft's Workflows webhooks
expect (the older Office 365 connector webhooks are being retired).

**SSRF**: unlike debcontrol, a rule here is self-service — any logged-in
user can set one up — so every user-supplied URL goes through
`app.services.webhook.validate_webhook_url` (public addresses only) when
the rule is saved and again right before sending, and redirects are never
followed. Telegram and Pushover only ever talk to their own fixed hosts.
`send(...)` returns an error message (or `None`) and never raises — a
failing push must never break the job that triggered it.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.db.models.notification_channel import NotificationChannel
from app.services.webhook import UnsafeWebhookTargetError, redact_url, validate_webhook_url

C = NotificationChannel

CHANNEL_NAMES: dict[str, str] = {
    C.EMAIL.value: "E-mail",
    C.WEBHOOK.value: "Webhook",
    C.NTFY.value: "ntfy",
    C.GOTIFY.value: "Gotify",
    C.TELEGRAM.value: "Telegram",
    C.DISCORD.value: "Discord",
    C.PUSHOVER.value: "Pushover",
    C.MATTERMOST.value: "Mattermost",
    C.SLACK.value: "Slack",
    C.TEAMS.value: "Microsoft Teams",
}
# Channels whose `webhook_url` is required (the plain webhook included).
URL_CHANNELS = frozenset(
    {
        C.WEBHOOK.value,
        C.NTFY.value,
        C.GOTIFY.value,
        C.DISCORD.value,
        C.MATTERMOST.value,
        C.SLACK.value,
        C.TEAMS.value,
    }
)
# Channels that can't send without a token.
TOKEN_CHANNELS = frozenset({C.GOTIFY.value, C.TELEGRAM.value, C.PUSHOVER.value})
# Channels with an optional token.
OPTIONAL_TOKEN_CHANNELS = frozenset({C.NTFY.value})
RECIPIENT_CHANNELS = frozenset({C.TELEGRAM.value, C.PUSHOVER.value})
# Everything `send` below handles (email and the plain webhook have their
# own senders).
PUSH_CHANNELS = frozenset(
    {
        C.NTFY.value,
        C.GOTIFY.value,
        C.TELEGRAM.value,
        C.DISCORD.value,
        C.PUSHOVER.value,
        C.MATTERMOST.value,
        C.SLACK.value,
        C.TEAMS.value,
    }
)

_TIMEOUT_SECONDS = 10
# Each service's own message size limits.
_TELEGRAM_MAX = 4096
_DISCORD_MAX = 2000
_PUSHOVER_TITLE_MAX = 250
_PUSHOVER_MESSAGE_MAX = 1024
_MATTERMOST_MAX = 16383
_SLACK_MAX = 3000
_TEAMS_MAX = 20000


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _ntfy_request(url: str) -> tuple[str, str]:
    """`https://ntfy.sh/topic` -> (`https://ntfy.sh/`, "topic") — ntfy's
    JSON publishing posts to the server root with the topic in the body,
    which keeps a non-ASCII title intact (HTTP headers can't carry it)."""
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    base_path, _, topic = path.rpartition("/")
    base = urlunsplit((parts.scheme, parts.netloc, base_path + "/", "", ""))
    return base, topic


def build_request(
    channel: str,
    *,
    url: str | None,
    token: str | None,
    recipient: str | None,
    subject: str,
    body: str,
) -> tuple[str, dict[str, Any]]:
    """`(url, httpx request kwargs)` for one push — pure, so each service's
    exact request shape is testable without a network. Raises ValueError
    when the rule is missing something the channel needs."""
    if channel in URL_CHANNELS and not url:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} URL configured.")
    if channel in TOKEN_CHANNELS and not token:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} token configured.")
    if channel in RECIPIENT_CHANNELS and not recipient:
        raise ValueError(f"No {CHANNEL_NAMES.get(channel, channel)} recipient configured.")
    if channel == C.NTFY.value:
        assert url is not None
        base, topic = _ntfy_request(url)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return base, {
            "json": {"topic": topic, "title": subject, "message": body},
            "headers": headers,
        }
    if channel == C.GOTIFY.value:
        assert url is not None
        return f"{url.rstrip('/')}/message", {
            "json": {"title": subject, "message": body, "priority": 5},
            "headers": {"X-Gotify-Key": token or ""},
        }
    if channel == C.TELEGRAM.value:
        return f"https://api.telegram.org/bot{token}/sendMessage", {
            "json": {"chat_id": recipient, "text": _clip(f"{subject}\n\n{body}", _TELEGRAM_MAX)}
        }
    if channel == C.DISCORD.value:
        assert url is not None
        return url, {"json": {"content": _clip(f"**{subject}**\n{body}", _DISCORD_MAX)}}
    if channel == C.PUSHOVER.value:
        return "https://api.pushover.net/1/messages.json", {
            "data": {
                "token": token,
                "user": recipient,
                "title": _clip(subject, _PUSHOVER_TITLE_MAX),
                "message": _clip(body, _PUSHOVER_MESSAGE_MAX),
            }
        }
    if channel == C.MATTERMOST.value:
        assert url is not None
        return url, {"json": {"text": _clip(f"**{subject}**\n{body}", _MATTERMOST_MAX)}}
    if channel == C.SLACK.value:
        assert url is not None
        return url, {"json": {"text": _clip(f"*{subject}*\n{body}", _SLACK_MAX)}}
    if channel == C.TEAMS.value:
        assert url is not None
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {"type": "TextBlock", "text": subject, "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": _clip(body, _TEAMS_MAX), "wrap": True},
            ],
        }
        return url, {
            "json": {
                "type": "message",
                "attachments": [
                    {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}
                ],
            }
        }
    raise ValueError(f'"{channel}" is not a push channel.')


async def send(
    channel: str,
    *,
    url: str | None,
    token: str | None,
    recipient: str | None,
    subject: str,
    body: str,
) -> str | None:
    """Deliver one push; returns an error message, or `None` on success.
    Never raises."""
    try:
        target, kwargs = build_request(
            channel, url=url, token=token, recipient=recipient, subject=subject, body=body
        )
        if channel in URL_CHANNELS:
            # Self-service rules: a user-supplied URL is re-checked at send
            # time too (a DNS answer can change after the rule was saved).
            await asyncio.to_thread(validate_webhook_url, target)
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.post(target, **kwargs)
        if response.status_code >= 300:
            return f"HTTP {response.status_code}"
        return None
    except UnsafeWebhookTargetError as exc:
        return str(exc)
    except Exception as exc:
        # Never echo a URL back into the log — Telegram's carries the token.
        message = str(exc).replace(token, "***") if token else str(exc)
        if url:
            message = message.replace(url, redact_url(url))
        return message[:2000] or exc.__class__.__name__


def delivery_target(channel: str, url: str | None, recipient: str | None) -> str:
    """What the delivery history shows as a push's target — never a token
    or a secret URL path."""
    if channel == C.TELEGRAM.value:
        return f"Telegram chat {recipient}"
    if channel == C.PUSHOVER.value:
        return f"Pushover {recipient}"
    return redact_url(url) if url else CHANNEL_NAMES.get(channel, channel)
