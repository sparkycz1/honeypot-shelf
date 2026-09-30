"""The fuzz targets. Each takes raw bytes and feeds them to one parser or
guard the way untrusted input would reach it, then checks the contract:

- a parser of honeypot output (`app.ssh.*`) never raises — a compromised or
  broken honeypot must not be able to crash a poll or a sweep;
- an OpenCanary log line always becomes an event the database accepts
  (bounded strings, a real port or none), whatever the attacker put in it;
- a guard that rejects input does so with its documented error, never
  anything else;
- whatever a security guard lets through really has the property it
  promises (`safe_local_path` returns a same-site path).

Plain Python on purpose: `fuzz.run` drives these under Atheris, and
`tests/test_fuzz_targets.py` runs them on every OS over a seed corpus.
"""

from __future__ import annotations

import contextlib
import json
import posixpath
import uuid
from collections.abc import Callable
from datetime import datetime
from types import SimpleNamespace
from typing import Any, cast

from app.auth.ssh_keys import InvalidSshPublicKeyError, parse_ssh_public_keys
from app.db.models.honeypot import Honeypot
from app.services.honeypot_events import build_event
from app.services.honeypot_tags import parse_tag_names_from_text
from app.ssh.canary_activity import parse_read_output
from app.ssh.facts import parse_facts_output
from app.ssh.logs import is_path_allowed, parse_directory_listing
from app.ssh.monitoring import parse_monitoring_output
from app.ssh.opencanary_config import OPENCANARY_MODULES, field_value, parse_config
from app.ssh.packages import parse_packages_output
from app.ssh.platform_detect import UnsupportedPlatformError, parse_detect_output
from app.ssh.readiness import parse_readiness_output
from app.ssh.readonly import parse_status
from app.ssh.services import parse_services_output
from app.ssh.updates import (
    parse_apt_simulated_changes,
    parse_apt_upgradable_packages,
    parse_flatpak_upgradable_output,
    parse_flatpak_upgradable_packages,
    parse_package_snapshot,
    parse_snap_upgradable_output,
    parse_snap_upgradable_packages,
    parse_upgradable_output,
)
from app.web.redirects import safe_local_path
from app.web.routes.api_v1_events import _parse_iso

# `build_event` only reads the honeypot's id.
_HONEYPOT = cast(Honeypot, SimpleNamespace(id=uuid.UUID(int=1)))


def _text(data: bytes) -> str:
    # asyncssh hands command output over decoded the same lenient way.
    return data.decode("utf-8", errors="replace")


def facts(data: bytes) -> None:
    parse_facts_output(_text(data))


def packages(data: bytes) -> None:
    parse_packages_output(_text(data))


def services(data: bytes) -> None:
    parse_services_output(_text(data))


def monitoring(data: bytes) -> None:
    parse_monitoring_output(_text(data))


def directory_listing(data: bytes) -> None:
    parse_directory_listing(_text(data))


def log_path(data: bytes) -> None:
    """The Logs tab's file/directory path — only ever something inside an
    allowed prefix, however it's spelled."""
    path = _text(data)
    if is_path_allowed(path, ["/var/log"]):
        normalized = posixpath.normpath(path)
        assert normalized == "/var/log" or normalized.startswith("/var/log/")


def readiness(data: bytes) -> None:
    parse_readiness_output(_text(data))


def readonly_status(data: bytes) -> None:
    parse_status(_text(data))


def platform_detect(data: bytes) -> None:
    with contextlib.suppress(UnsupportedPlatformError):
        parse_detect_output(_text(data))


def updates(data: bytes) -> None:
    text = _text(data)
    parse_apt_upgradable_packages(text)
    parse_upgradable_output(text)
    parse_flatpak_upgradable_packages(text)
    parse_flatpak_upgradable_output(text)
    parse_snap_upgradable_packages(text)
    parse_snap_upgradable_output(text)
    parse_apt_simulated_changes(text)
    parse_package_snapshot(text)


def canary_log(data: bytes) -> None:
    """What an OpenCanary log poll reads — attacker-influenced end to end
    (usernames, paths, user agents, even whole forged lines on a
    compromised honeypot)."""
    result = parse_read_output(_text(data))
    for payload in result.events:
        event = build_event(_HONEYPOT, payload)
        assert isinstance(event.event_type, str) and len(event.event_type) <= 100
        assert event.src_ip is None or (isinstance(event.src_ip, str) and len(event.src_ip) <= 64)
        for port in (event.src_port, event.dst_port):
            assert port is None or (type(port) is int and 0 <= port <= 65535)
        assert isinstance(event.occurred_at, datetime)


def canary_event(data: bytes) -> None:
    """One log line straight into `build_event`, skipping the poll framing —
    lets the fuzzer spend its time on the payload's shape."""
    try:
        payload: Any = json.loads(_text(data))
    except (ValueError, RecursionError):
        return
    if isinstance(payload, dict):
        canary_log(json.dumps(payload).encode() + b"\n\n===READ=== 0\n")


def opencanary_config(data: bytes) -> None:
    try:
        config = parse_config(_text(data))
    except ValueError:  # json.JSONDecodeError included
        return
    assert isinstance(config, dict)
    for module in OPENCANARY_MODULES:
        for field_def in module.fields:
            field_value(config, field_def)


def ssh_keys(data: bytes) -> None:
    with contextlib.suppress(InvalidSshPublicKeyError):
        parse_ssh_public_keys(_text(data))


def redirect(data: bytes) -> None:
    result = safe_local_path(_text(data), "/dashboard")
    assert result.startswith("/")
    assert not result.startswith("//")
    assert "\\" not in result
    assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in result)


def event_time_filter(data: bytes) -> None:
    parsed = _parse_iso(_text(data))
    assert parsed is None or parsed.tzinfo is not None


def tags(data: bytes) -> None:
    for name in parse_tag_names_from_text(_text(data)):
        assert name and name == name.strip()


TARGETS: dict[str, Callable[[bytes], None]] = {
    fn.__name__: fn
    for fn in (
        facts,
        packages,
        services,
        monitoring,
        directory_listing,
        log_path,
        readiness,
        readonly_status,
        platform_detect,
        updates,
        canary_log,
        canary_event,
        opencanary_config,
        ssh_keys,
        redirect,
        event_time_filter,
        tags,
    )
}
