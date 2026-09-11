"""Low-level syslog transport, shared by every syslog forwarder this app
has: `app.audit_syslog` (global, audit log entries — configured on
Settings → Integrations) and `app.services.honeypot_event_syslog`
(per-company, honeypot alerts only — configured on each Company's own
page). Both send RFC 5424 messages whose MSG part is a compact JSON
object (see each module's own `_json_message`/equivalent) — not the
free-text `key="value"` shape an earlier version of this file used, per
explicit instruction: every syslog message this app sends must be JSON,
easy for a receiver (a SIEM's own parser, `jq`, ...) to consume without
a bespoke grammar.

`SyslogProtocol`/`DEFAULT_SYSLOG_PORT` live here (not on `AppSettings`,
where the first, audit-only target was originally defined) so both the
global (`AppSettings.syslog_*`) and per-company (`Company.syslog_*`)
config columns can share the exact same Postgres enum type and transport
code without one model importing the other's module.

Supports plain UDP, plain TCP, and TCP-over-TLS ("encrypted syslog", for
sending to a SIEM over a network you don't fully trust). The two TCP
modes use RFC 6587 octet-counting framing (`"<length> <message>"`) so the
receiver can split a stream into messages — UDP needs no framing, since
one datagram is already one message.

All socket I/O is blocking (`socket`/`ssl` are simplest for one-shot
sends like this — no long-lived connection to manage), so `send_syslog`
always runs it off the event loop via `asyncio.to_thread`, same pattern
`app.auth.ldap`'s synchronous `ldap3` calls use.
"""

from __future__ import annotations

import asyncio
import enum
import socket
import ssl

_SOCKET_TIMEOUT_SECONDS = 3


class SyslogProtocol(enum.StrEnum):
    """UDP and TCP are plaintext (RFC 6587 octet-counting framing for TCP;
    UDP needs none); TLS wraps the same TCP framing in a TLS session, for
    sending to a SIEM (e.g. Wazuh) over an untrusted network."""

    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


DEFAULT_SYSLOG_PORT = 514


def send_syslog_sync(host: str, port: int, protocol: SyslogProtocol, message: str) -> None:
    """Blocking. Raises `OSError` on any transport failure — callers decide
    how to log/swallow it (a syslog target being unreachable must never be
    allowed to affect the action that triggered the message, but what
    "the action" even is differs per caller)."""
    if protocol == SyslogProtocol.UDP:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SOCKET_TIMEOUT_SECONDS)
            sock.sendto(message.encode("utf-8"), (host, port))
        return

    body = message.encode("utf-8")
    framed = str(len(body)).encode("ascii") + b" " + body
    with socket.create_connection((host, port), timeout=_SOCKET_TIMEOUT_SECONDS) as sock:
        if protocol == SyslogProtocol.TLS:
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(framed)
        else:
            sock.sendall(framed)


async def send_syslog(host: str, port: int, protocol: SyslogProtocol, message: str) -> None:
    """Async wrapper around `send_syslog_sync` — still raises `OSError` on
    failure, same reasoning."""
    await asyncio.to_thread(send_syslog_sync, host, port, protocol, message)
