"""The actual downloaded GeoIP database bytes — a singleton row, separate
from `AppSettings` (which only holds the *configuration*: enabled, the two
URLs, the refresh interval) because this table can hold a multi-megabyte
blob and `AppSettings` is read on essentially every request
(`get_or_create_app_settings`); keeping the blob elsewhere means that read
stays cheap regardless of GeoIP being configured at all.

Written only by `app.services.geoip.refresh_geoip_database` (the
Settings page's "Download now" button, and the periodic Celery task on
`AppSettings.geoip_refresh_interval_hours`) — never by a migration or
bundled with the image; see that module's own docstring for the full
download/parse/fallback flow and how `app.services.geoip.get_reader`
caches this in memory per process.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SINGLETON_ID = 1


class GeoipDatabase(Base):
    __tablename__ = "geoip_database"

    id: Mapped[int] = mapped_column(primary_key=True)

    # The raw .mmdb file bytes (already decompressed/extracted if the
    # source served a .tar.gz) — `None` until the first successful
    # download. A reader is built from this via a temp file per process
    # (the underlying C extension needs a real path/fd, not a bytes
    # buffer) — see `app.services.geoip`.
    mmdb_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Which configured URL this data actually came from, for the Settings
    # page's own status line — "primary" or "backup".
    source: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # When `mmdb_data` was last successfully replaced. `None` means never.
    updated_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Every attempt (success or failure) touches this, so "last checked" is
    # visible even when every attempt so far has failed and `updated_at`
    # stays `None`.
    last_attempted_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # The error from the most recent *failed* attempt — cleared on the next
    # success. `None` while `last_attempted_at` is also `None` (never
    # tried), or right after a successful attempt.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
