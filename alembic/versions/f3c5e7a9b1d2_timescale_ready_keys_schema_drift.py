"""Time column in the history tables' primary keys; old schema drift fixed.

- honeypot_monitoring_samples, honeypot_reachability_samples and
  honeypot_events get (id, <time column>) as primary key, which a
  TimescaleDB hypertable requires (app/db/timescale.py). Plain PostgreSQL
  just rebuilds the key index once.
- Drift between an older migration and the models, found by `alembic
  check`: honeypot_notes.created_at and saved_log_views.created_at were
  created without a time zone; they become timestamptz (the values were
  always written as UTC).

Ported from debcontrol 0.129.0 (f2b4d6e8a0c1).

Revision ID: f3c5e7a9b1d2
Revises: e2b4c6d8f0a1
Create Date: 2026-10-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f3c5e7a9b1d2"
down_revision: str | None = "e2b4c6d8f0a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_HISTORY_TABLES = (
    ("honeypot_monitoring_samples", "sampled_at"),
    ("honeypot_reachability_samples", "checked_at"),
    ("honeypot_events", "occurred_at"),
)

_NAIVE_TIMESTAMPS = (
    ("honeypot_notes", "created_at"),
    ("saved_log_views", "created_at"),
)


def upgrade() -> None:
    for table, time_column in _HISTORY_TABLES:
        op.drop_constraint(f"pk_{table}", table, type_="primary")
        op.create_primary_key(f"pk_{table}", table, ["id", time_column])

    for table, column in _NAIVE_TIMESTAMPS:
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"TYPE timestamp with time zone USING {column} AT TIME ZONE 'UTC'"
        )


def downgrade() -> None:
    for table, column in _NAIVE_TIMESTAMPS:
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"TYPE timestamp without time zone USING {column} AT TIME ZONE 'UTC'"
        )

    for table, _time_column in _HISTORY_TABLES:
        op.drop_constraint(f"pk_{table}", table, type_="primary")
        op.create_primary_key(f"pk_{table}", table, ["id"])
