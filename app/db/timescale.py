"""TimescaleDB, when the database has it (the bundled `timescaledb` Compose
profile, or an own PostgreSQL with `CREATE EXTENSION timescaledb`).

Nothing here changes the schema Alembic manages: the same tables exist on
PostgreSQL and TimescaleDB, so data moves freely between the two
(scripts/db_import.sh). On TimescaleDB this module adds, idempotently:

- the three history tables (OpenCanary events, monitoring and
  reachability samples) as hypertables with one-day chunks;
- compression (TimescaleDB's columnstore) of chunks, segmented by
  honeypot: the samples after 7 days, the events only after 30, so the
  Events page's searches by source address or alert type stay fast over
  the recent month.

`python -m app.db.timescale` runs it in the `migrate` service after
`alembic upgrade head` (a no-op without TimescaleDB). Retention stays the
app's own (Settings, per honeypot): the purge jobs drop whole chunks where
every honeypot's retention allows it (`drop_old_chunks`) and delete the
rest row by row as on PostgreSQL.

Ported from debcontrol 0.129.0, without its continuous aggregates: nothing
here reads per-day availability (debcontrol's status page does), and the
Dashboard's daily trend already has its own rollup (`CompanySnapshot`).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import asyncpg
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine

log = logging.getLogger(__name__)

CHUNK_INTERVAL = "1 day"


@dataclass(frozen=True)
class Hypertable:
    table: str
    time_column: str
    segment_by: str
    compress_after_days: int


MONITORING = Hypertable("honeypot_monitoring_samples", "sampled_at", "honeypot_id", 7)
REACHABILITY = Hypertable("honeypot_reachability_samples", "checked_at", "honeypot_id", 7)
EVENTS = Hypertable("honeypot_events", "occurred_at", "honeypot_id", 30)
HYPERTABLES = (MONITORING, REACHABILITY, EVENTS)

_EXTENSION_SQL = "SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')"

# Per process: whether the database has TimescaleDB. Computed on first use
# (after the fork, so every worker child asks once); the stack restarts
# whenever the database changes.
_enabled: bool | None = None


def reset_cache() -> None:
    global _enabled
    _enabled = None


async def enabled(session: AsyncSession) -> bool:
    """Whether this database has the TimescaleDB extension."""
    global _enabled
    if _enabled is None:
        if session.get_bind().dialect.name != "postgresql":
            _enabled = False
        else:
            _enabled = bool(await session.scalar(text(_EXTENSION_SQL)))
    return _enabled


async def _scalar(conn: AsyncConnection | AsyncSession, sql: str, **params: Any) -> Any:
    return (await conn.execute(text(sql), params)).scalar()


async def _ensure_hypertable(conn: AsyncConnection, table: Hypertable) -> bool:
    """Make `table` a hypertable (moving existing rows into chunks).
    Returns whether it was converted now."""
    exists = await _scalar(
        conn,
        "SELECT 1 FROM timescaledb_information.hypertables "
        "WHERE hypertable_schema = 'public' AND hypertable_name = :t",
        t=table.table,
    )
    if exists:
        return False
    await conn.execute(
        text(
            f"SELECT create_hypertable('public.{table.table}', "
            f"by_range('{table.time_column}', INTERVAL '{CHUNK_INTERVAL}'), "
            "migrate_data => true, create_default_indexes => false)"
        )
    )
    return True


async def _ensure_compression(conn: AsyncConnection, table: Hypertable) -> None:
    enabled_now = await _scalar(
        conn,
        "SELECT compression_enabled FROM timescaledb_information.hypertables "
        "WHERE hypertable_schema = 'public' AND hypertable_name = :t",
        t=table.table,
    )
    if enabled_now:
        return
    await conn.execute(
        text(
            f"ALTER TABLE public.{table.table} SET ("
            "timescaledb.enable_columnstore = true, "
            f"timescaledb.segmentby = '{table.segment_by}', "
            f"timescaledb.orderby = '{table.time_column} DESC')"
        )
    )


async def _apply_compression_policy(conn: AsyncConnection, table: Hypertable) -> bool:
    """Compress `table`'s chunks once older than its age. Returns whether
    the policy changed."""
    current = await _scalar(
        conn,
        "SELECT config->>'compress_after' FROM timescaledb_information.jobs "
        "WHERE proc_name = 'policy_compression' AND hypertable_schema = 'public' "
        "AND hypertable_name = :t",
        t=table.table,
    )
    wanted = f"{table.compress_after_days} days"
    if current == wanted:
        return False
    if current is not None:
        await conn.execute(text(f"CALL remove_columnstore_policy('public.{table.table}')"))
    await conn.execute(
        text(
            f"CALL add_columnstore_policy('public.{table.table}', "
            f"after => INTERVAL '{table.compress_after_days} days')"
        )
    )
    return True


async def setup(conn: AsyncConnection) -> list[str]:
    """Bring a TimescaleDB database to the layout above. Returns what was
    done, for the log; empty when nothing was needed or the database has
    no TimescaleDB."""
    if not await _scalar(conn, _EXTENSION_SQL):
        return []
    done: list[str] = []
    for table in HYPERTABLES:
        if await _ensure_hypertable(conn, table):
            done.append(f"{table.table}: hypertable")
        await _ensure_compression(conn, table)
        if await _apply_compression_policy(conn, table):
            done.append(f"{table.table}: compressed after {table.compress_after_days} days")
    return done


async def describe(session: AsyncSession) -> dict[str, Any] | None:
    """What the Settings page and `GET /api/v1/settings` show: the
    extension's version and each history table's compression age (None
    when the database has no TimescaleDB)."""
    if not await enabled(session):
        return None
    version = await _scalar(
        session, "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
    )
    rows = await session.execute(
        text(
            "SELECT hypertable_name, config->>'compress_after' FROM timescaledb_information.jobs "
            "WHERE proc_name = 'policy_compression' AND hypertable_schema = 'public'"
        )
    )
    compress_after: dict[str, int | None] = {}
    for name, value in rows.all():
        days = str(value or "").split(" ", 1)[0]
        compress_after[str(name)] = int(days) if days.isdigit() else None
    return {"version": version, "compress_after_days": compress_after}


async def drop_old_chunks(session: AsyncSession, table: Hypertable, older_than: datetime) -> int:
    """Drop `table`'s chunks that hold only rows older than `older_than`.
    Returns how many went."""
    result = await session.execute(
        text(
            "SELECT count(*) FROM drop_chunks(CAST(:r AS regclass), "
            "older_than => CAST(:t AS timestamptz))"
        ),
        {"r": f"public.{table.table}", "t": older_than},
    )
    await session.commit()
    return int(result.scalar() or 0)


_VERSIONS_SQL = (
    "SELECT e.extversion, a.default_version FROM pg_extension e "
    "JOIN pg_available_extensions a ON a.name = e.extname WHERE e.extname = 'timescaledb'"
)


async def update_extension(conn: AsyncConnection, database_url: str) -> str | None:
    """Move the installed extension up to the version the server ships.

    A new TimescaleDB image leaves an existing database on its old
    extension version (the image keeps the old library for exactly that)
    until someone runs `ALTER EXTENSION timescaledb UPDATE`. That has to be
    the very first statement of a session: any earlier query, even
    SQLAlchemy's own connection setup, loads the old library and the update
    then fails. So `conn` only reads the versions, and the update runs on a
    bare asyncpg connection of its own. Returns "2.31.0 -> 2.32.0" when it
    updated, None when nothing was needed or possible (no TimescaleDB, or a
    role that doesn't own the extension: then it logs what an administrator
    has to run)."""
    row = (await conn.execute(text(_VERSIONS_SQL))).first()
    if row is None or row[0] == row[1]:
        return None
    installed, available = str(row[0]), str(row[1])
    dsn = make_url(database_url).set(drivername="postgresql")
    try:
        bare = await asyncpg.connect(dsn.render_as_string(hide_password=False))
        try:
            await bare.execute("ALTER EXTENSION timescaledb UPDATE")
        finally:
            await bare.close()
    except (asyncpg.PostgresError, OSError) as exc:
        log.warning(
            "timescaledb: the extension is %s, the server ships %s, and updating it failed (%s). "
            "Run `ALTER EXTENSION timescaledb UPDATE` as the extension's owner, "
            'first thing in a fresh "psql -X" session.',
            installed,
            available,
            type(exc).__name__,
        )
        return None
    return f"{installed} -> {available}"


async def _main() -> int:
    from app.core.config import get_settings

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    engine = create_async_engine(get_settings().database_url, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            if conn.dialect.name != "postgresql":
                return 0
            updated = await update_extension(conn, get_settings().database_url)
            if updated:
                log.info("timescaledb: extension updated %s", updated)
        # A new connection for the rest: the one above has the old
        # library loaded.
        await engine.dispose()
        async with engine.connect() as conn:
            for line in await setup(conn):
                log.info("timescaledb: %s", line)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
