"""Redact webhook URLs already stored in the notification delivery history

A webhook URL's path is usually its secret (Discord, Slack, ntfy...), but up
to 0.45.0 the delivery history (`notification_logs.target`, and an error
message that happened to echo the URL) stored it verbatim. New rows are
redacted at write time (`app.services.webhook.redact_url`); this scrubs the
existing ones the same way. Data only, no schema change; not reversible
(the point).

Revision ID: b7c9d1e3f5a7
Revises: 9a1b2c3d4e5f
Create Date: 2026-10-02
"""
from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlsplit

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c9d1e3f5a7"
down_revision: str | None = "9a1b2c3d4e5f"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def _redact(url: str) -> str:
    # A frozen copy of `app.services.webhook.redact_url` — a migration must
    # not change behaviour when the app code it would import does.
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "…"
    if not parts.scheme or not parts.hostname:
        return "…"
    host = parts.hostname + (f":{port}" if port else "")
    rest = "/…" if parts.path.strip("/") or parts.query else ""
    return f"{parts.scheme}://{host}{rest}"


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, target, error FROM notification_logs "
            "WHERE target LIKE 'http://%' OR target LIKE 'https://%'"
        )
    ).fetchall()
    for row_id, target, error in rows:
        redacted = _redact(target)
        if redacted == target:
            continue
        bind.execute(
            sa.text("UPDATE notification_logs SET target = :target, error = :error WHERE id = :id"),
            {
                "id": row_id,
                "target": redacted,
                "error": error.replace(target, redacted) if error else error,
            },
        )


def downgrade() -> None:
    # The original URLs are gone on purpose.
    pass
