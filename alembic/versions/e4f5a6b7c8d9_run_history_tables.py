"""initialize_runs and scheduled_task_runs history tables

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-09-08

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4f5a6b7c8d9"
down_revision: str | None = "d3e4f5a6b7c8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "initialize_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_name", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "finished_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=True),
        sa.Column("output", sa.Text(), nullable=False),
        sa.Column("triggered_by", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_initialize_runs")),
    )

    op.create_table(
        "scheduled_task_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column(
            "fired_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "outcome",
            sa.Enum("success", "failure", name="scheduled_task_run_outcome"),
            nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("attempted", sa.Integer(), nullable=False),
        sa.Column("skipped", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["scheduled_tasks.id"],
            name=op.f("fk_scheduled_task_runs_task_id_scheduled_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scheduled_task_runs")),
    )
    op.create_index(
        "ix_scheduled_task_runs_task_id_fired_at",
        "scheduled_task_runs",
        ["task_id", "fired_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scheduled_task_runs_task_id"),
        "scheduled_task_runs",
        ["task_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scheduled_task_runs_task_id"), table_name="scheduled_task_runs")
    op.drop_index("ix_scheduled_task_runs_task_id_fired_at", table_name="scheduled_task_runs")
    op.drop_table("scheduled_task_runs")
    sa.Enum(name="scheduled_task_run_outcome").drop(op.get_bind(), checkfirst=True)

    op.drop_table("initialize_runs")
