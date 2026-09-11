"""Forward honeypot *alerts* (real OpenCanary events — never the internal/
operational log lines `app.services.opencanary_logtypes.is_internal_logtype`
already filters out before a `HoneypotEvent` row is ever created) to each
company's own syslog target, configured on that Company's own page
(`Company.syslog_*`).

**Deliberately separate from `app.audit_syslog`** (the global target on
Settings → Integrations, which carries every audit log entry and never a
honeypot alert): in a multi-tenant deployment, "send every alert to one
shared syslog server" is usually wrong — company A's SOC shouldn't see
company B's alert traffic (or vice versa), and each may already run its
own SIEM. This module answers "where does *this* company's own alert
traffic go" per `HoneypotEvent.company_id` (already denormalized onto the
row — see that model's own docstring — so no join back through `Honeypot`
is needed to find it), while the global target keeps covering everything
else app-wide regardless of company (see `app.audit_syslog`'s own
docstring for the fuller split).

Same best-effort/fire-and-forget contract as the audit forwarder: the
`HoneypotEvent` row is always the source of truth (queryable via the
Activity tab/`GET /api/v1/events`), this is only ever a live mirror of
it, and a delivery failure here must never affect event ingestion itself.
Same transport (`app.services.syslog_transport`) and same "MSG part is a
compact JSON object" convention `app.audit_syslog` uses.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import TYPE_CHECKING

from app.services.opencanary_logtypes import logtype_label
from app.services.syslog_transport import send_syslog

if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.honeypot import Honeypot
    from app.db.models.honeypot_event import HoneypotEvent

logger = logging.getLogger("HoneyHive.honeypot_event_syslog")

# RFC 5424 facility 4, "security/authorization messages" — a closer fit
# for an intrusion-detection alert than facility 1 ("user-level
# messages"), which app.audit_syslog uses for ordinary audit entries.
_FACILITY_SECURITY = 4
_SEVERITY_WARNING = 4  # every alert is treated the same severity — OpenCanary itself reports none.


def _rfc5424_message(event: HoneypotEvent, honeypot: Honeypot, company: Company) -> str:
    pri = _FACILITY_SECURITY * 8 + _SEVERITY_WARNING
    timestamp = event.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    hostname = socket.gethostname() or "-"
    msg_id = event.event_type.replace(" ", "_")[:32]
    payload = {
        "event": "honeypot_alert",
        "id": str(event.id),
        "timestamp": timestamp,
        "company": company.name,
        "honeypot": honeypot.name,
        "honeypot_ip": honeypot.ip_address,
        "type": event.event_type,
        "label": logtype_label(event.event_type),
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "source": event.source,
        "raw": event.raw,
    }
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # "HoneyHive" is the APP-NAME field; "-" (no PROCID), then MSGID, then
    # "-" for STRUCTURED-DATA (none), then the JSON message itself.
    return f"<{pri}>1 {timestamp} {hostname} HoneyHive - {msg_id} - {body}"


async def forward_honeypot_event_to_syslog(
    company: Company, honeypot: Honeypot, event: HoneypotEvent
) -> None:
    """No-op unless this company has `syslog_enabled` and a host
    configured. Never raises — logs a warning and swallows any failure,
    since a company's SIEM being unreachable must never be allowed to
    affect event ingestion itself."""
    if not company.syslog_enabled or not company.syslog_host:
        return
    message = _rfc5424_message(event, honeypot, company)
    try:
        await send_syslog(
            company.syslog_host, company.syslog_port, company.syslog_protocol, message
        )
    except OSError:
        logger.warning(
            "Failed to forward honeypot alert to syslog %s:%s for company %s",
            company.syslog_host,
            company.syslog_port,
            company.name,
            exc_info=True,
        )
