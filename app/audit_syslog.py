"""Forward audit log entries to an external syslog server (e.g. a SIEM),
configured on Settings → Integrations (`AppSettings.syslog_*`).

Best-effort, fire-and-forget: the `AuditLogEntry` row already written by
`app.audit.log_event` is always the source of truth (hash-chained,
queryable, exportable) — this is only ever a live mirror of it, and a
delivery failure here must never affect the action being audited or raise
back into the caller. See `log_event`'s call into `forward_to_syslog`.

This is HoneyHive's **global** syslog target — every audit log entry
(every human-initiated mutation across the whole app: honeypot/company/
user CRUD, logins, settings changes, ...), regardless of company. It
never carries honeypot *alerts* (OpenCanary events) — those never go
through `app.audit.log_event` at all (see that module's own docstring on
what gets audited), and have their own, separate, per-company syslog
target instead (`app.services.honeypot_event_syslog`, configured on each
Company's own page) — see that module's docstring for why a single global
target isn't the right shape for alert traffic in a multi-tenant
deployment.

Actual transport (UDP/TCP/TCP-over-TLS, RFC 5424 framing) lives in
`app.services.syslog_transport`, shared with the per-company forwarder
below. Every message this app sends to syslog is a compact JSON object
as the RFC 5424 MSG part — not free-text `key="value"` pairs — so a
receiver's own parser (or `jq`) never needs a bespoke grammar for it.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import TYPE_CHECKING

from app.services.syslog_transport import send_syslog

if TYPE_CHECKING:
    from app.db.models.app_settings import AppSettings
    from app.db.models.audit_log import AuditLogEntry

logger = logging.getLogger("HoneyHive.audit_syslog")

_FACILITY_USER = 1  # RFC 5424 facility 1, "user-level messages".


def _severity_for_outcome(outcome_value: str) -> int:
    # RFC 5424 severities: lower number = more severe.
    if outcome_value == "success":
        return 5  # notice
    if outcome_value == "denied":
        return 4  # warning
    return 3  # error ("failure")


def _rfc5424_message(entry: AuditLogEntry) -> str:
    pri = _FACILITY_USER * 8 + _severity_for_outcome(entry.outcome.value)
    timestamp = entry.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    hostname = socket.gethostname() or "-"
    msg_id = (entry.action or "-").replace(" ", "_")[:32]
    payload = {
        "event": "audit",
        "id": str(entry.id),
        "timestamp": timestamp,
        "action": entry.action,
        "actor": entry.actor,
        "ip": entry.ip_address,
        "outcome": entry.outcome.value,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "target_label": entry.target_label,
        "summary": entry.summary,
        "details": entry.details,
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # "HoneypotShelf" is the APP-NAME field; "-" (no PROCID), then MSGID, then
    # "-" for STRUCTURED-DATA (none), then the JSON message itself.
    return f"<{pri}>1 {timestamp} {hostname} HoneypotShelf - {msg_id} - {body}"


async def forward_to_syslog(app_settings: AppSettings, entry: AuditLogEntry) -> None:
    """No-op unless `syslog_enabled` and a host is configured. Never raises
    — logs a warning and swallows any failure, since a SIEM being
    unreachable must never be allowed to affect the action being audited."""
    if not app_settings.syslog_enabled or not app_settings.syslog_host:
        return
    message = _rfc5424_message(entry)
    try:
        await send_syslog(
            app_settings.syslog_host,
            app_settings.syslog_port,
            app_settings.syslog_protocol,
            message,
        )
    except OSError:
        logger.warning(
            "Failed to forward audit entry to syslog %s:%s",
            app_settings.syslog_host,
            app_settings.syslog_port,
            exc_info=True,
        )
