"""`app.services.honeypot_events` — the OpenCanary-payload -> HoneypotEvent
builder used by the SSH log poller (the only way an event is ingested
now — see the module's own docstring for the removed push endpoint)."""

from __future__ import annotations

import uuid
from datetime import UTC

from app.db.models.honeypot import Honeypot
from app.services.honeypot_events import _coerce_port, build_event, parse_occurred_at


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

    event = build_event(honeypot, payload)

    assert event.honeypot_id == honeypot.id
    assert event.event_type == "4002"
    assert event.src_ip == "203.0.113.9"
    assert event.src_port == 51234
    assert event.dst_port == 22
    assert event.source == "ssh_poll"
    assert event.raw == payload


def test_build_event_defaults_event_type_to_unknown_when_absent():
    honeypot = _make_honeypot()
    event = build_event(honeypot, {})
    assert event.event_type == "UNKNOWN"
    assert event.source == "ssh_poll"


def test_build_event_coerces_a_string_port_to_an_int():
    """Regression guard for a real bug found live: at least one OpenCanary
    module emits src_port/dst_port as a numeric *string* ("42206") rather
    than a number - asyncpg (unlike the SQLite test harness, which
    coerces silently) refuses to bind a str into an Integer column at
    all, failing the whole insert - taking down every other event
    batched in the same poll with it, permanently, since the byte offset
    only advances on a successful commit."""
    honeypot = _make_honeypot()
    payload = {"logtype": "4002", "src_port": "42206", "dst_port": "22"}

    event = build_event(honeypot, payload)

    assert event.src_port == 42206
    assert isinstance(event.src_port, int)
    assert event.dst_port == 22
    assert isinstance(event.dst_port, int)


def test_coerce_port_accepts_int_and_numeric_string():
    assert _coerce_port(22) == 22
    assert _coerce_port("22") == 22
    assert _coerce_port(" 22 ") == 22


def test_coerce_port_returns_none_for_anything_unparseable():
    assert _coerce_port(None) is None
    assert _coerce_port("") is None
    assert _coerce_port("not-a-port") is None
    assert _coerce_port(True) is None  # bool is an int subclass, not a real port
    assert _coerce_port([22]) is None
