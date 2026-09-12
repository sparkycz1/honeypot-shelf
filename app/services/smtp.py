"""SMTP relay for outbound email — the actual `smtplib` send behind
Notifications (`app.services.notifications`). Configuration itself lives
in Settings → Integrations (`AppSettings.smtp_*` — host/port/encryption/
username/password/from address/from name, same shape and same
encrypted-secret convention as the LDAP/OIDC sections next to it).

`send_email` is deliberately the *only* thing this module does — deciding
*when* an email goes out (which event, which recipient, which template)
is `app.services.notifications`'s job entirely; this module doesn't know
what a "notification" is at all, just how to hand one message to a
configured relay.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings, SmtpEncryption


class SmtpNotConfiguredError(Exception):
    """Raised by `send_email` when `AppSettings.smtp_enabled` is off or no
    host is set — callers (`app.services.notifications`) treat this as a
    silent no-op, never a hard failure."""


def send_email(app_settings: AppSettings, *, to_address: str, subject: str, body: str) -> None:
    """Synchronous SMTP send (stdlib `smtplib`) — always run this via
    `asyncio.to_thread` from an async caller, the same "sync library,
    async caller" seam every Celery task in `app.tasks.jobs` already
    crosses for its own synchronous protocols (`app.auth.ldap`,
    `app.services.syslog_transport`), rather than adding an async SMTP
    client dependency for this one feature. One connection per recipient —
    simple and correct at the small recipient counts a notification
    realistically has.

    Raises `SmtpNotConfiguredError` if SMTP isn't enabled/configured, or
    lets `smtplib`'s own exceptions propagate otherwise — the caller
    decides how to log/swallow either case (see
    `app.services.notifications.notify`, which never lets a failed send
    break the background job that triggered it)."""
    if not app_settings.smtp_enabled or not app_settings.smtp_host:
        raise SmtpNotConfiguredError("SMTP is not enabled/configured")

    message = EmailMessage()
    message["Subject"] = subject
    from_name = app_settings.smtp_from_name or "Honeypot Shelf"
    from_address = app_settings.smtp_from_address or app_settings.smtp_username or to_address
    message["From"] = f"{from_name} <{from_address}>"
    message["To"] = to_address
    message.set_content(body)

    connect: type[smtplib.SMTP] = (
        smtplib.SMTP_SSL if app_settings.smtp_encryption == SmtpEncryption.SSL_TLS else smtplib.SMTP
    )
    with connect(app_settings.smtp_host, app_settings.smtp_port, timeout=15) as client:
        if app_settings.smtp_encryption == SmtpEncryption.STARTTLS:
            client.starttls()
        if app_settings.smtp_username and app_settings.smtp_password_encrypted:
            client.login(
                app_settings.smtp_username, decrypt_secret(app_settings.smtp_password_encrypted)
            )
        client.send_message(message)
