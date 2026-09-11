"""SMTP relay for outbound email notifications — configuration only, for
now.

This deliberately does **not** send anything yet. What's built in this
round is just Settings → Integrations' SMTP section
(`AppSettings.smtp_*` — host/port/encryption/username/password/from
address/from name, same shape and same encrypted-secret convention as
the LDAP/OIDC sections next to it) so the relay itself can be configured
and saved ahead of the actual notification feature, per explicit
instruction ("add SMTP so we can send notifications — the rest in a
follow-up task").

**Planned, not yet built**: an actual `send_email(...)` here (`smtplib`,
matching the "blocking I/O off the event loop via `asyncio.to_thread`"
pattern `app.services.syslog_transport`/`app.auth.ldap` already use for
their own synchronous protocols), and whatever decides *when* an email
goes out — most likely a new per-company or per-user notification
preference once that design is settled, mirroring how `app.services.
honeypot_event_syslog` is *company*-scoped while `app.audit_syslog` is
global. Nothing calls into this module yet.
"""

from __future__ import annotations
