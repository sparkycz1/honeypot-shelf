"""`app.services.honeypot_events` — shared OpenCanary-payload -> HoneypotEvent
builder used by both the push ingest endpoint and the SSH log poller."""

from __future__ import annotations

import uuid
from datetime import UTC

from app.db.models.honeypot import Honeypot
from app.services.honeypot_events import EventSource, build_event, parse_occurred_at


def _make_honeypot() -> Honeypot:
    return Honeypot(id=uuid.uuid4(), name="acme-honey1")


def test_parse_occurred_at_parses_opencanarys_local_time_format():
    parsed = parse_occurred_at({"local_time": "2026-01-02 03:04:05.678900"})
    assert parsed.year == 2026
    assert parsed.month == 1
    assert parsed.day == 2
    assert parsed.tzinfo == UTC


def test_parse_occurred_at_falls_back_to_now_for_missing_or_malformed_timestamp():
    parsed = parse_occurred_at({})
    assert parsed.tzinfo == UTC

    parsed = parse_occurred_at({"local_time": "not a timestamp"})
    assert parsed.tzinfo == UTC


def test_build_event_promotes_the_common_opencanary_fields():
    honeypot = _make_honeypot()
    payload = {
        "logtype": "4002",
        "src_host": "203.0.113.9",
        "src_port": 51234,
        "dst_port": 22,
        "local_time": "2026-01-02 03:04:05.000000",
    }

    event = build_event(honeypot, payload, source=EventSource.SSH_POLL)

    assert event.honeypot_id == honeypot.id
    assert event.event_type == "4002"
    assert event.src_ip == "203.0.113.9"
    assert event.src_port == 51234
    assert event.dst_port == 22
    assert event.source == "ssh_poll"
    assert event.raw == payload


def test_build_event_defaults_event_type_to_unknown_when_absent():
    honeypot = _make_honeypot()
    event = build_event(honeypot, {}, source=EventSource.PUSH)
    assert event.event_type == "UNKNOWN"
    assert event.source == "push"
