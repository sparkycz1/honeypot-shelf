"""app.audit_syslog — the global, audit-log-only syslog target (Settings
-> Integrations). Every message's MSG part must be JSON (explicit
instruction), never the old free-text `key="value"` shape."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.audit_syslog import _rfc5424_message, forward_to_syslog
from app.db.models.audit_log import AuditLogEntry, AuditOutcome

pytestmark = pytest.mark.asyncio


def _make_entry(**overrides: object) -> AuditLogEntry:
    defaults: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        "action": "honeypot.create",
        "actor": "admin",
        "ip_address": "203.0.113.5",
        "outcome": AuditOutcome.SUCCESS,
        "target_type": "honeypot",
        "target_id": "abc-123",
        "target_label": "acme-honey1",
        "summary": 'Created honeypot "acme-honey1"',
        "details": {"company_id": "xyz"},
    }
    defaults.update(overrides)
    return AuditLogEntry(**defaults)


def test_rfc5424_message_body_is_valid_json():
    entry = _make_entry()
    message = _rfc5424_message(entry)
    # <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    header, _, body = message.rpartition(" - ")
    assert header.startswith("<")
    parsed = json.loads(body)
    assert parsed["event"] == "audit"
    assert parsed["action"] == "honeypot.create"
    assert parsed["actor"] == "admin"
    assert parsed["outcome"] == "success"
    assert parsed["target_type"] == "honeypot"
    assert parsed["details"] == {"company_id": "xyz"}


def test_rfc5424_message_has_no_embedded_newlines():
    entry = _make_entry(summary="multi\nline\nsummary")
    message = _rfc5424_message(entry)
    assert "\n" not in message


async def test_forward_to_syslog_noop_when_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.audit_syslog.send_syslog",
        lambda *a, **kw: calls.append((a, kw)),
    )

    class FakeSettings:
        syslog_enabled = False
        syslog_host = "siem.example.com"

    await forward_to_syslog(FakeSettings(), _make_entry())  # type: ignore[arg-type]
    assert calls == []


async def test_forward_to_syslog_sends_when_enabled(monkeypatch):
    sent = {}

    async def fake_send(host, port, protocol, message):
        sent["host"] = host
        sent["port"] = port
        sent["protocol"] = protocol
        sent["message"] = message

    monkeypatch.setattr("app.audit_syslog.send_syslog", fake_send)

    class FakeSettings:
        syslog_enabled = True
        syslog_host = "siem.example.com"
        syslog_port = 514
        syslog_protocol = "udp"

    await forward_to_syslog(FakeSettings(), _make_entry())  # type: ignore[arg-type]
    assert sent["host"] == "siem.example.com"
    body = sent["message"].rpartition(" - ")[2]
    json.loads(body)  # doesn't raise
