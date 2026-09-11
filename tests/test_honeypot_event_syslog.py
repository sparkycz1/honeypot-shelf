"""app.services.honeypot_event_syslog — each company's own syslog target
for its honeypot *alerts* only (never audit log entries — that's
app.audit_syslog's job, and never internal/operational OpenCanary log
noise — never even stored as a HoneypotEvent in the first place). Every
message's MSG part must be JSON (explicit instruction)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.services.honeypot_event_syslog import _rfc5424_message, forward_honeypot_event_to_syslog
from app.services.syslog_transport import SyslogProtocol

pytestmark = pytest.mark.asyncio


def _make_trio() -> tuple[Company, Honeypot, HoneypotEvent]:
    company = Company(id=uuid.uuid4(), name="Acme")
    honeypot = Honeypot(
        id=uuid.uuid4(), company_id=company.id, name="acme-honey1", ip_address="10.0.0.5"
    )
    event = HoneypotEvent(
        id=uuid.uuid4(),
        honeypot_id=honeypot.id,
        company_id=company.id,
        event_type="4002",
        occurred_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        src_ip="203.0.113.7",
        src_port=51500,
        dst_port=22,
        raw={"logtype": 4002, "src_host": "203.0.113.7"},
        source="ssh_poll",
    )
    return company, honeypot, event


def test_rfc5424_message_body_is_valid_json_with_alert_fields():
    company, honeypot, event = _make_trio()
    message = _rfc5424_message(event, honeypot, company)
    header, _, body = message.rpartition(" - ")
    assert header.startswith("<")
    parsed = json.loads(body)
    assert parsed["event"] == "honeypot_alert"
    assert parsed["company"] == "Acme"
    assert parsed["honeypot"] == "acme-honey1"
    assert parsed["type"] == "4002"
    assert parsed["src_ip"] == "203.0.113.7"
    assert parsed["raw"] == {"logtype": 4002, "src_host": "203.0.113.7"}


async def test_forward_noop_when_company_syslog_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.services.honeypot_event_syslog.send_syslog",
        lambda *a, **kw: calls.append((a, kw)),
    )
    company, honeypot, event = _make_trio()
    company.syslog_enabled = False
    company.syslog_host = "siem.acme.example.com"

    await forward_honeypot_event_to_syslog(company, honeypot, event)
    assert calls == []


async def test_forward_sends_when_company_syslog_enabled(monkeypatch):
    sent = {}

    async def fake_send(host, port, protocol, message):
        sent["host"] = host
        sent["message"] = message

    monkeypatch.setattr("app.services.honeypot_event_syslog.send_syslog", fake_send)
    company, honeypot, event = _make_trio()
    company.syslog_enabled = True
    company.syslog_host = "siem.acme.example.com"
    company.syslog_port = 514
    company.syslog_protocol = SyslogProtocol.UDP

    await forward_honeypot_event_to_syslog(company, honeypot, event)
    assert sent["host"] == "siem.acme.example.com"
    body = sent["message"].rpartition(" - ")[2]
    parsed = json.loads(body)
    assert parsed["company"] == "Acme"
