"""Human-readable labels for OpenCanary's `logtype` alert ids.

OpenCanary logs one JSON object per alert with a numeric `logtype` field
(e.g. `4002` for an SSH login attempt) — the full list of `LOG_*` integer
constants lives in OpenCanary's own
https://github.com/thinkst/opencanary/blob/master/opencanary/logger.py.
Neither `HoneypotEvent.event_type` (this app's own storage — see
`app.services.honeypot_events`) nor OpenCanary's log file carries a human
name, just the bare integer as a string — this module is the one place that
number gets turned into something a person can read, for both the Activity
tab (`app.web.routes.honeypots`) and the Dashboard's recent-events list.

`_MODULE_OF` groups each id under the same short module "key" the Honeypot
Config tab's module editor already uses (`app.ssh.opencanary_config`) — the
Activity tab's per-module chart buckets by this, not by the ~30 individual
ids, so the chart stays readable even though the id list is long.
"""

from __future__ import annotations

from collections.abc import Callable

# id -> human label. Kept as a flat dict (not an enum) — like
# `HoneypotEvent.event_type` itself, this list belongs to OpenCanary, not
# this app, and can grow across an OpenCanary upgrade without a Honeypot Shelf
# release; an id missing here just falls back to showing the raw number
# (see `logtype_label` below).
_LABELS: dict[int, str] = {
    1000: "System boot",
    1001: "General message",
    1002: "Debug message",
    1003: "Error",
    1004: "Ping",
    1005: "Configuration saved",
    1006: "Example event",
    2000: "FTP login attempt",
    2001: "FTP authentication initiated",
    3000: "HTTP GET request",
    3001: "HTTP POST login attempt",
    3002: "HTTP unimplemented method",
    3003: "HTTP redirect",
    4000: "SSH new connection",
    4001: "SSH remote version sent",
    4002: "SSH login attempt",
    5000: "SMB file opened",
    5001: "Port scan (SYN)",
    5002: "Port scan (Nmap OS detection)",
    5003: "Port scan (Nmap NULL)",
    5004: "Port scan (Nmap Xmas)",
    5005: "Port scan (Nmap FIN)",
    6001: "Telnet login attempt",
    6002: "Telnet connection made",
    7001: "HTTP proxy login attempt",
    8001: "MySQL login attempt",
    9001: "MSSQL login (SQL auth)",
    9002: "MSSQL login (Windows auth)",
    9003: "MySQL connection made",
    10001: "TFTP request",
    11001: "NTP monlist request",
    12001: "VNC connection",
    13001: "SNMP command",
    14001: "RDP connection",
    15001: "SIP request",
    16001: "Git clone request",
    17001: "Redis command",
    18001: "TCP banner: connection made",
    18002: "TCP banner: keepalive connection",
    18003: "TCP banner: keepalive secret received",
    18004: "TCP banner: keepalive data received",
    18005: "TCP banner: data received",
    19001: "LLMNR query response",
    20001: "MongoDB login attempt",
    **{99000 + n: f"Custom event {n}" for n in range(10)},
}

# id -> the Honeypot Config tab's module "key" (app.ssh.opencanary_config) —
# used to bucket the Activity tab's per-module chart. `None`/missing means
# "not a service module alert" (OpenCanary's own base/system log lines,
# logtype 1000-1006).
_MODULE_OF: dict[int, str] = {
    2000: "ftp",
    2001: "ftp",
    3000: "http",
    3001: "http",
    3002: "http",
    3003: "http",
    4000: "ssh",
    4001: "ssh",
    4002: "ssh",
    5000: "smb",
    5001: "portscan",
    5002: "portscan",
    5003: "portscan",
    5004: "portscan",
    5005: "portscan",
    6001: "telnet",
    6002: "telnet",
    7001: "httpproxy",
    8001: "mysql",
    9001: "mssql",
    9002: "mssql",
    9003: "mysql",
    10001: "tftp",
    11001: "ntp",
    12001: "vnc",
    13001: "snmp",
    14001: "rdp",
    15001: "sip",
    16001: "git",
    17001: "redis",
    18001: "tcpbanner",
    18002: "tcpbanner",
    18003: "tcpbanner",
    18004: "tcpbanner",
    18005: "tcpbanner",
    19001: "llmnr",
    20001: "mongodb",
}


# OpenCanary's own internal/operational logging (`Logger.log()` calls it
# makes about itself — process startup, a raised exception, a config
# save, ...), not a honeypot "someone touched a fake service" alert. A
# real live instance emits these constantly (every module registration on
# every start, and — found live — every crash-loop restart), which would
# otherwise flood the Activity tab/Dashboard with "General message"/
# "Debug message" noise having nothing to do with actual attacker
# activity. `app.tasks.jobs`'s SSH log poll skips storing a
# `HoneypotEvent` for one of these — see `is_internal_logtype`.
_INTERNAL_LOGTYPES = frozenset({1000, 1001, 1002, 1003, 1004, 1005, 1006})


def is_internal_logtype(logtype: object) -> bool:
    """True for one of OpenCanary's own internal/operational log lines
    (see `_INTERNAL_LOGTYPES`'s own comment) — never a real alert, so a
    caller building `HoneypotEvent` rows from raw log lines should skip
    it. A `logtype` this module doesn't recognize at all (missing, not
    numeric, or a real alert id) is never treated as internal — only the
    known, deliberately-enumerated internal ids are."""
    as_int = _as_int(logtype)
    return as_int is not None and as_int in _INTERNAL_LOGTYPES


def _as_int(logtype: object) -> int | None:
    if isinstance(logtype, bool):
        return None
    if isinstance(logtype, int):
        return logtype
    if isinstance(logtype, str) and logtype.strip().lstrip("-").isdigit():
        return int(logtype)
    return None


def logtype_label(logtype: object) -> str:
    """A human label for a `HoneypotEvent.event_type`/raw `logtype` value —
    `"SSH login attempt"` for `4002`/`"4002"`. Falls back to the raw value
    (stringified) for anything not in `_LABELS`, e.g. a `logtype` from a
    newer OpenCanary release this list hasn't been updated for yet, or
    already-human text a custom forwarder sent instead of the numeric id —
    never an error, same tolerance every other OpenCanary-payload parser in
    this app has."""
    as_int = _as_int(logtype)
    if as_int is not None and as_int in _LABELS:
        return _LABELS[as_int]
    return str(logtype)


def module_key(logtype: object) -> str | None:
    """The Honeypot Config tab's module `key` this alert belongs to, or
    `None` for a base/system log line or an id this list doesn't
    recognize."""
    as_int = _as_int(logtype)
    if as_int is None:
        return None
    return _MODULE_OF.get(as_int)


def localized_logtype_label(translate: Callable[[str], str], logtype: object) -> str:
    """Same as `logtype_label`, but through `translate` (a pre-bound
    `lambda key: t(request, key)`, see `app.web.templating.t`) for every
    one of the ~30 fixed ids above — i18n key `opencanary.event_label.
    <id>`, present in every `app/i18n/locales/*.json` file. Only for the
    two template-rendering call sites (`app.services.
    canary_activity_history`'s `build_activity_history`/
    `summarize_recent_events`, called from the Activity tab and the
    Dashboard) — every other caller of `logtype_label` (the REST API, CSV/
    JSON export, the per-company syslog forwarder) deliberately keeps the
    plain English label instead: a machine-consumed value shouldn't vary
    by whichever session happened to render the page that triggered it.
    The 10 generated "Custom event N" ids and any id this list doesn't
    recognize at all fall back to the same plain `logtype_label` a
    non-localized caller gets — not worth ten more i18n keys for ids
    OpenCanary itself doesn't name."""
    as_int = _as_int(logtype)
    if as_int is not None and as_int in _LABELS and as_int < 99000:
        return translate(f"opencanary.event_label.{as_int}")
    return logtype_label(logtype)
