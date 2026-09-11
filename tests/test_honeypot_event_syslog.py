"""app.services.honeypot_event_syslog — each company's own syslog target
for its honeypot *alerts* only (never audit log entries — that's
app.audit_syslog's job, and never internal/operational OpenCanary log
noise — never even stored as a HoneypotEvent in the first place), plus
the fleet-wide target ("All honeypots" -> Integrations,
AppSettings.fleet_alert_syslog_*) that fires *in addition to* the
company's own. Every message's MSG part must be JSON (explicit
instruction)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.db.models.company import Company
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.services.honeypot_event_syslog import _rfc5424_message, forward_honeypot_event_to_syslog
from app.services.syslog_transport import SyslogProtocol

pytestmark = pytest.mark.asyncio


def _make_trio() -> tuple[Company, Honeypot, HoneypotEvent]:
    company = Company(id=uuid.uuid4(), name="Acme")
    honeypot = Honeypot(
        id=uuid.uuid4(), companies=[company], name="acme-honey1", ip_address="10.0.0.5"
    )
    event = HoneypotEvent(
        id=uuid.uuid4(),
        honeypot_id=honeypot.id,
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
    _company, honeypot, event = _make_trio()
    message = _rfc5424_message(event, honeypot)
    header, _, body = message.rpartition(" - ")
    assert header.startswith("<")
    parsed = json.loads(body)
    assert parsed["event"] == "honeypot_alert"
    assert parsed["companies"] == ["Acme"]
    assert parsed["honeypot"] == "acme-honey1"
    assert parsed["type"] == "4002"
    assert parsed["src_ip"] == "203.0.113.7"
    assert parsed["raw"] == {"logtype": 4002, "src_host": "203.0.113.7"}


async def test_forward_noop_when_neither_target_configured(monkeypatch, db_session_factory):
    calls = []
    monkeypatch.setattr(
        "app.services.honeypot_event_syslog.send_syslog",
        lambda *a, **kw: calls.append((a, kw)),
    )
    company, honeypot, event = _make_trio()
    company.syslog_enabled = False
    company.syslog_host = "siem.acme.example.com"

    async with db_session_factory() as db:
        await forward_honeypot_event_to_syslog(db, honeypot, event)
    assert calls == []


async def test_forward_sends_when_company_syslog_enabled(monkeypatch, db_session_factory):
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

    async with db_session_factory() as db:
        await forward_honeypot_event_to_syslog(db, honeypot, event)
    assert sent["host"] == "siem.acme.example.com"
    body = sent["message"].rpartition(" - ")[2]
    parsed = json.loads(body)
    assert parsed["companies"] == ["Acme"]


async def test_forward_also_sends_to_the_fleet_wide_target_when_configured(
    monkeypatch, db_session_factory
):
    """The "All honeypots" page's own target fires *in addition to* the
    company's own — both can be on at once, independently."""
    sent = []

    async def fake_send(host, port, protocol, message):
        sent.append(host)

    monkeypatch.setattr("app.services.honeypot_event_syslog.send_syslog", fake_send)
    company, honeypot, event = _make_trio()
    company.syslog_enabled = True
    company.syslog_host = "siem.acme.example.com"
    company.syslog_port = 514
    company.syslog_protocol = SyslogProtocol.UDP

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_alert_syslog_enabled = True
        app_settings.fleet_alert_syslog_host = "siem.fleet.example.com"
        await db.commit()

        await forward_honeypot_event_to_syslog(db, honeypot, event)

    assert set(sent) == {"siem.acme.example.com", "siem.fleet.example.com"}


async def test_forward_fleet_wide_only_when_company_target_not_configured(
    monkeypatch, db_session_factory
):
    sent = []

    async def fake_send(host, port, protocol, message):
        sent.append(host)

    monkeypatch.setattr("app.services.honeypot_event_syslog.send_syslog", fake_send)
    company, honeypot, event = _make_trio()  # company syslog left disabled

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_alert_syslog_enabled = True
        app_settings.fleet_alert_syslog_host = "siem.fleet.example.com"
        await db.commit()

        await forward_honeypot_event_to_syslog(db, honeypot, event)

    assert sent == ["siem.fleet.example.com"]


async def test_forward_a_failed_company_send_does_not_block_the_fleet_send(
    monkeypatch, db_session_factory
):
    """One target being unreachable must never stop the other from being
    tried."""
    sent = []

    async def fake_send(host, port, protocol, message):
        if host == "siem.acme.example.com":
            raise OSError("connection refused")
        sent.append(host)

    monkeypatch.setattr("app.services.honeypot_event_syslog.send_syslog", fake_send)
    company, honeypot, event = _make_trio()
    company.syslog_enabled = True
    company.syslog_host = "siem.acme.example.com"

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.fleet_alert_syslog_enabled = True
        app_settings.fleet_alert_syslog_host = "siem.fleet.example.com"
        await db.commit()

        await forward_honeypot_event_to_syslog(db, honeypot, event)

    assert sent == ["siem.fleet.example.com"]
