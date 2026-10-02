"""Push notification channels (ntfy, Gotify, Telegram, Discord, Pushover)
and team chats (Mattermost, Slack, Microsoft Teams) — ported from
debcontrol's `app.services.push_channels`, with this app's self-service
rules SSRF-checking every user-supplied URL."""

from __future__ import annotations

import re
import types
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.notification_log import NotificationChannel, NotificationLog
from app.db.models.notification_rule import NotificationRule, NotificationScope
from app.db.models.user import User
from app.services import push_channels
from tests.conftest import create_company

PUBLIC = "https://93.184.216.34"


def _fake_client(post):
    """Stands in for `httpx.AsyncClient` inside `push_channels` only — the
    test client itself is an `httpx.AsyncClient` too, so patching the class
    globally would swallow the test's own requests."""

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, **kwargs):
            return await post(url, **kwargs)

    return types.SimpleNamespace(AsyncClient=FakeClient)


def _csrf_from(response) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    assert match, "no csrf_token found in response"
    return match.group(1)


async def _make_honeypot(db_session_factory) -> object:
    company = await create_company(db_session_factory)
    async with db_session_factory() as db:
        honeypot = Honeypot(companies=[await db.get(Company, company.id)], name="push-honey")
        db.add(honeypot)
        await db.commit()
        return honeypot.id


# --- Request shapes -------------------------------------------------------------


@pytest.mark.parametrize(
    ("channel", "url", "token", "recipient", "expected_url"),
    [
        ("ntfy", "https://ntfy.sh/alerts", None, None, "https://ntfy.sh/"),
        ("gotify", "https://gotify.lan/", "tok", None, "https://gotify.lan/message"),
        ("telegram", None, "123:abc", "42", "https://api.telegram.org/bot123:abc/sendMessage"),
        ("discord", "https://discord.com/api/webhooks/1/x", None, None, None),
        ("pushover", None, "app", "user", "https://api.pushover.net/1/messages.json"),
        ("mattermost", "https://mm.example.com/hooks/x", None, None, None),
        ("slack", "https://hooks.slack.com/services/x", None, None, None),
        ("teams", "https://example.webhook.office.com/x", None, None, None),
    ],
)
def test_build_request_targets(channel, url, token, recipient, expected_url):
    target, kwargs = push_channels.build_request(
        channel, url=url, token=token, recipient=recipient, subject="S", body="B"
    )
    assert target == (expected_url or url)
    assert "json" in kwargs or "data" in kwargs


def test_chat_payload_shapes():
    def payload(channel: str) -> dict[str, Any]:
        return push_channels.build_request(
            channel, url="https://x.example/h", token=None, recipient=None, subject="S", body="B"
        )[1]["json"]

    assert payload("mattermost") == {"text": "**S**\nB"}
    assert payload("slack") == {"text": "*S*\nB"}
    teams = payload("teams")
    assert teams["type"] == "message"
    card = teams["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert [block["text"] for block in card["content"]["body"]] == ["S", "B"]


def test_ntfy_sends_topic_in_body_and_optional_bearer():
    _, kwargs = push_channels.build_request(
        "ntfy", url="https://ntfy.sh/alerts", token="tk_1", recipient=None, subject="Ř", body="B"
    )
    assert kwargs["json"] == {"topic": "alerts", "title": "Ř", "message": "B"}
    assert kwargs["headers"] == {"Authorization": "Bearer tk_1"}


@pytest.mark.parametrize(
    ("channel", "kwargs"),
    [
        ("discord", {"url": None, "token": None, "recipient": None}),
        ("gotify", {"url": "https://g.lan", "token": None, "recipient": None}),
        ("telegram", {"url": None, "token": "t", "recipient": None}),
    ],
)
def test_build_request_refuses_an_incomplete_rule(channel, kwargs):
    with pytest.raises(ValueError):
        push_channels.build_request(channel, subject="S", body="B", **kwargs)


def test_delivery_target_never_shows_a_secret():
    assert push_channels.delivery_target("telegram", None, "42") == "Telegram chat 42"
    assert push_channels.delivery_target("pushover", None, "u") == "Pushover u"
    assert (
        push_channels.delivery_target("slack", "https://hooks.slack.com/services/T/B/x", None)
        == "https://hooks.slack.com/…"
    )


@pytest.mark.asyncio
async def test_send_refuses_a_private_url_before_any_request(monkeypatch):
    async def no_network(url, **kwargs):
        raise AssertionError("no request may be made")

    monkeypatch.setattr(push_channels, "httpx", _fake_client(no_network))
    error = await push_channels.send(
        "slack", url="http://127.0.0.1/hook", token=None, recipient=None, subject="S", body="B"
    )
    assert error is not None and "non-public" in error


@pytest.mark.asyncio
async def test_send_masks_the_token_in_an_error(monkeypatch):
    async def boom(url, **kwargs):
        raise httpx.ConnectError(f"cannot reach {url}")

    monkeypatch.setattr(push_channels, "httpx", _fake_client(boom))
    error = await push_channels.send(
        "telegram", url=None, token="123:secret", recipient="42", subject="S", body="B"
    )
    assert error is not None and "123:secret" not in error


# --- The rule form ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_creating_a_telegram_rule_stores_the_token_encrypted(client, db_session_factory):
    honeypot_id = await _make_honeypot(db_session_factory)
    form = await client.get("/account/notifications")
    assert 'value="telegram"' in form.text and 'value="teams"' in form.text

    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Telegram rule",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "telegram",
            "channel_token": "123:secret",
            "channel_recipient": "42",
            "webhook_url": "https://ignored.example/x",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
    assert rule.delivery_channel == NotificationChannel.TELEGRAM
    assert rule.channel_recipient == "42"
    assert rule.webhook_url is None
    assert rule.channel_token_encrypted is not None
    assert b"123:secret" not in rule.channel_token_encrypted
    assert decrypt_secret(rule.channel_token_encrypted) == "123:secret"


@pytest.mark.asyncio
async def test_a_token_channel_needs_a_token_and_a_recipient(client, db_session_factory):
    honeypot_id = await _make_honeypot(db_session_factory)
    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Pushover rule",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "pushover",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Pushover needs a token." in response.text
    assert "Pushover needs a recipient" in response.text


@pytest.mark.asyncio
async def test_a_chat_rule_refuses_a_private_url(client, db_session_factory):
    honeypot_id = await _make_honeypot(db_session_factory)
    form = await client.get("/account/notifications")
    response = await client.post(
        "/account/notifications",
        data={
            "csrf_token": _csrf_from(form),
            "name": "Slack rule",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "slack",
            "webhook_url": "http://169.254.169.254/latest",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "non-public address" in response.text
    async with db_session_factory() as db:
        assert (await db.execute(select(NotificationRule))).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_editing_with_a_blank_token_keeps_the_stored_one(client, db_session_factory):
    honeypot_id = await _make_honeypot(db_session_factory)
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None
        rule = NotificationRule(
            user_id=user.id,
            name="Gotify",
            scope=NotificationScope.HONEYPOT,
            honeypots=[honeypot],
            delivery_channel=NotificationChannel.GOTIFY,
            webhook_url=f"{PUBLIC}/",
            channel_token_encrypted=encrypt_secret("kept"),
            notify_on_alert=True,
        )
        db.add(rule)
        await db.commit()
        rule_id = rule.id

    page = await client.get(f"/account/notifications/{rule_id}/edit")
    assert "kept" not in page.text
    response = await client.post(
        f"/account/notifications/{rule_id}/edit",
        data={
            "csrf_token": _csrf_from(page),
            "name": "Gotify renamed",
            "scope": "honeypot",
            "honeypot_ids": str(honeypot_id),
            "delivery_channel": "gotify",
            "webhook_url": f"{PUBLIC}/",
            "channel_token": "",
            "notify_on_alert": "on",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        rule = await db.get(NotificationRule, rule_id)
        assert rule is not None
    assert rule.name == "Gotify renamed"
    assert rule.channel_token_encrypted is not None
    assert decrypt_secret(rule.channel_token_encrypted) == "kept"


@pytest.mark.asyncio
async def test_a_push_test_send_is_logged_with_a_redacted_target(
    client, db_session_factory, monkeypatch
):
    honeypot_id = await _make_honeypot(db_session_factory)
    sent: list[tuple[str, dict[str, Any]]] = []

    async def fake_post(url, **kwargs):
        sent.append((url, kwargs))
        return httpx.Response(200)

    monkeypatch.setattr(push_channels, "httpx", _fake_client(fake_post))
    monkeypatch.setattr("app.services.push_channels.validate_webhook_url", lambda url: None)

    secret_url = "https://chat.example.com/hooks/very-secret"
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None
        honeypot = await db.get(Honeypot, honeypot_id)
        assert honeypot is not None
        rule = NotificationRule(
            user_id=user.id,
            name="Mattermost",
            scope=NotificationScope.HONEYPOT,
            honeypots=[honeypot],
            delivery_channel=NotificationChannel.MATTERMOST,
            webhook_url=secret_url,
            notify_on_alert=True,
        )
        db.add(rule)
        await db.commit()
        rule_id = rule.id

    form = await client.get("/account/notifications")
    response = await client.post(
        f"/account/notifications/{rule_id}/test",
        data={"csrf_token": _csrf_from(form)},
        follow_redirects=False,
    )
    assert "test_sent=1" in response.headers["location"]
    assert sent and sent[0][0] == secret_url
    assert "text" in sent[0][1]["json"]

    async with db_session_factory() as db:
        entry = (await db.execute(select(NotificationLog))).scalar_one()
    assert entry.channel == NotificationChannel.MATTERMOST
    assert entry.target == "https://chat.example.com/…"
