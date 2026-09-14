"""Forward honeypot *alerts* (real OpenCanary events — never the internal/
operational log lines `app.services.opencanary_logtypes.is_internal_logtype`
already filters out before a `HoneypotEvent` row is ever created) to each
company's own syslog target, configured on that Company's own page
(`Company.syslog_*`) — **and**, if configured, to the fleet-wide target on
the "All honeypots" page's own Integrations tab
(`AppSettings.fleet_alert_syslog_*`). Both can be on at the same time for
the same event: a central, overarching SIEM alongside each tenant's own,
not a replacement for either.

**Deliberately separate from `app.audit_syslog`** (the global target on
Settings → Integrations, which carries every audit log entry and never a
honeypot alert): in a multi-tenant deployment, "send every alert to one
shared syslog server" is usually wrong — company A's SOC shouldn't see
company B's alert traffic (or vice versa), and each may already run its
own SIEM. This module answers "where does *this* alert's traffic go" by
walking the triggering honeypot's own `companies` (a honeypot can belong
to any number of them — see `app.db.models.company`'s module docstring)
and sending to every one that has forwarding configured, while the global
target keeps covering everything else app-wide regardless of company (see
`app.audit_syslog`'s own docstring for the fuller split).

Same best-effort/fire-and-forget contract as the audit forwarder: the
`HoneypotEvent` row is always the source of truth (queryable via the
Activity tab/`GET /api/v1/events`), this is only ever a live mirror of
it, and a delivery failure at either target must never affect event
ingestion itself, or delivery to the *other* target. Same transport
(`app.services.syslog_transport`) and same "MSG part is a compact JSON
object" convention `app.audit_syslog` uses.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import TYPE_CHECKING

from app.core.app_settings import get_or_create_app_settings
from app.services.opencanary_logtypes import logtype_label
from app.services.syslog_transport import SyslogProtocol, send_syslog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.db.models.honeypot import Honeypot
    from app.db.models.honeypot_event import HoneypotEvent

logger = logging.getLogger("Honeypot Shelf.honeypot_event_syslog")

# RFC 5424 facility 4, "security/authorization messages" — a closer fit
# for an intrusion-detection alert than facility 1 ("user-level
# messages"), which app.audit_syslog uses for ordinary audit entries.
_FACILITY_SECURITY = 4
_SEVERITY_WARNING = 4  # every alert is treated the same severity — OpenCanary itself reports none.


def _rfc5424_message(event: HoneypotEvent, honeypot: Honeypot) -> str:
    pri = _FACILITY_SECURITY * 8 + _SEVERITY_WARNING
    timestamp = event.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    hostname = socket.gethostname() or "-"
    msg_id = event.event_type.replace(" ", "_")[:32]
    payload = {
        "event": "honeypot_alert",
        "id": str(event.id),
        "timestamp": timestamp,
        "companies": [c.name for c in honeypot.companies],
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
    # "HoneypotShelf" is the APP-NAME field; "-" (no PROCID), then MSGID, then
    # "-" for STRUCTURED-DATA (none), then the JSON message itself.
    return f"<{pri}>1 {timestamp} {hostname} HoneypotShelf - {msg_id} - {body}"


async def _send(
    host: str, port: int, protocol: SyslogProtocol, message: str, *, target_label: str
) -> None:
    try:
        await send_syslog(host, port, protocol, message)
    except OSError:
        logger.warning(
            "Failed to forward honeypot alert to syslog %s:%s (%s)",
            host,
            port,
            target_label,
            exc_info=True,
        )


async def forward_honeypot_event_to_syslog(
    db: AsyncSession, honeypot: Honeypot, event: HoneypotEvent
) -> None:
    """Sends to whichever targets are actually configured — every one of
    `honeypot.companies`' own targets (`Company.syslog_*`) and/or the
    fleet-wide one (`AppSettings.fleet_alert_syslog_*`) — independently:
    one being unreachable, disabled, or unconfigured never affects any
    other. A no-op entirely if none are set up (including an unattached
    honeypot with no companies at all). Never raises — see this module's
    own docstring for why."""
    message = _rfc5424_message(event, honeypot)

    for company in honeypot.companies:
        if company.syslog_enabled and company.syslog_host:
            await _send(
                company.syslog_host,
                company.syslog_port,
                company.syslog_protocol,
                message,
                target_label=f"company {company.name!r}",
            )

    app_settings = await get_or_create_app_settings(db)
    if app_settings.fleet_alert_syslog_enabled and app_settings.fleet_alert_syslog_host:
        await _send(
            app_settings.fleet_alert_syslog_host,
            app_settings.fleet_alert_syslog_port,
            app_settings.fleet_alert_syslog_protocol,
            message,
            target_label="fleet-wide",
        )
