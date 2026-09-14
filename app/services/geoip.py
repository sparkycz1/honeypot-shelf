"""GeoIP lookups: resolves a public source IP to a country/city/lat-long
from a MaxMind-DB-format (`.mmdb`) database this app downloads itself —
never bundled with the image, since redistributing MaxMind's GeoLite2 data
isn't allowed under their license. See `AppSettings`'s own "GeoIP" section
for the two-URL/refresh-interval config and `app.db.models.geoip_database.
GeoipDatabase` for where the downloaded bytes actually live.

Two independent entry points:

- `refresh_geoip_database` — the download side. Tries `geoip_primary_url`,
  falls back to `geoip_backup_url` only if the primary fails outright
  (network error, bad HTTP status, unparseable file) — never load-balanced
  between the two. Called by the Settings page's "Download now" button and
  the periodic Celery task (`app.tasks.jobs.refresh_geoip_database`, on
  `AppSettings.geoip_refresh_interval_hours` — see `app.tasks.celery_app`
  for why that cadence is only re-read at Beat's own startup).
- `resolve`/`get_reader`/`lookup` — the read side, used both by
  `app.services.honeypot_events` (an ingested alert's `src_ip`) and
  `app.audit.log_event` (a request's source IP) to annotate a row *at
  write time*, not looked up again later — see this module's own
  `_ReaderCache` docstring for why a stale-for-up-to-an-hour in-process
  cache is the right trade-off here, and both those call sites for why
  "GeoIP isn't configured/downloaded yet" (returns `None`) is silently
  swallowed rather than raised: geo data is always a nice-to-have
  enrichment, never something a write should fail over.

Deliberately skips any IP that isn't publicly routable (`ipaddress.
ip_address(...).is_global`) — a honeypot's LAN-facing traffic, a login
through an internal reverse proxy that leaks a private address, or a
malformed value all have no real-world location to show, and MaxMind's own
database has no data for them anyway (a wasted lookup that just raises
`AddressNotFoundError`).
"""

from __future__ import annotations

import contextlib
import gzip
import io
import ipaddress
import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import geoip2.database
import geoip2.errors
import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

logger = logging.getLogger(__name__)

_DOWNLOAD_TIMEOUT_SECONDS = 60.0
# How long the in-process reader cache trusts its last check of
# GeoipDatabase.updated_at before re-querying it — bounds how long a
# freshly downloaded database can go unnoticed by an already-running web/
# worker process to at most this, while keeping the overwhelming majority
# of calls (every audit log write, every ingested honeypot event) down to
# one in-memory comparison, not a database round trip.
_RECHECK_INTERVAL = timedelta(hours=1)


class GeoipDownloadError(Exception):
    """Every configured URL failed (or none is configured at all) — see
    `GeoipDatabase.last_error` for the combined message, also raised here
    so the Settings page's "Download now" button can show it immediately
    without a second query."""


@dataclass(frozen=True)
class GeoLocation:
    country_code: str | None
    country_name: str | None
    city_name: str | None
    latitude: float | None
    longitude: float | None


def _extract_mmdb(data: bytes) -> bytes:
    """A source URL might serve a raw `.mmdb`, a plain gzip of one (a
    MaxMind "permalink" with `suffix=mmdb.gz`), or a gzipped tar (MaxMind's
    own default `.tar.gz`, which wraps the `.mmdb` inside a dated
    subdirectory) — detected from the bytes themselves, not the URL or a
    `suffix=` query param, since a backup URL might serve a differently
    shaped response than the primary one."""
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith(".mmdb"):
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        return extracted.read()
            raise GeoipDownloadError("Downloaded archive has no .mmdb file inside.")
    except tarfile.TarError:
        return data  # Not a tar archive - treat as a raw .mmdb already.


def _validate_mmdb(data: bytes) -> None:
    """Opens `data` as a real GeoIP database to confirm it parses at all,
    before it's ever saved as the new `GeoipDatabase.mmdb_data` — the
    underlying C extension needs a real path, not a bytes buffer (see
    `_ReaderCache` below), so this writes a throwaway temp file just for
    the check. Raises `GeoipDownloadError` on anything that isn't a valid
    MaxMind DB file."""
    fd, path = tempfile.mkstemp(suffix=".mmdb", prefix="honeypotshelf-geoip-validate-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        with geoip2.database.Reader(path):
            pass
    except Exception as exc:
        raise GeoipDownloadError(f"not a valid GeoIP database ({exc})") from exc
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


async def _fetch_and_validate(url: str) -> bytes:
    async with httpx.AsyncClient(
        timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
    mmdb_bytes = _extract_mmdb(response.content)
    _validate_mmdb(mmdb_bytes)
    return mmdb_bytes


async def refresh_geoip_database(db: AsyncSession, app_settings: AppSettings) -> GeoipDatabase:
    """Downloads a fresh database, updating the singleton `GeoipDatabase`
    row in place (creating it on first use, same as `get_or_create_app_
    settings`). Always records the attempt — `last_attempted_at` and, on
    failure, `last_error` — even when every URL fails, so the Settings
    page can show "last checked" independently of whether it ever
    succeeded. Raises `GeoipDownloadError` only after that recording, so a
    caller that doesn't care about the exception (the periodic Celery
    task) can just let it propagate to Celery's own retry/logging."""
    primary_url = (
        decrypt_secret(app_settings.geoip_primary_url_encrypted)
        if app_settings.geoip_primary_url_encrypted
        else None
    )
    backup_url = (
        decrypt_secret(app_settings.geoip_backup_url_encrypted)
        if app_settings.geoip_backup_url_encrypted
        else None
    )

    row = await db.get(GeoipDatabase, SINGLETON_ID)
    if row is None:
        row = GeoipDatabase(id=SINGLETON_ID)
        db.add(row)

    attempted_at = datetime.now(UTC)
    row.last_attempted_at = attempted_at

    errors: list[str] = []
    for label, url in (("primary", primary_url), ("backup", backup_url)):
        if not url:
            continue
        try:
            mmdb_bytes = await _fetch_and_validate(url)
        except Exception as exc:
            logger.warning("GeoIP database download from %s URL failed: %s", label, exc)
            errors.append(f"{label}: {exc}")
            continue
        row.mmdb_data = mmdb_bytes
        row.source = label
        row.updated_at = attempted_at
        row.last_error = None
        await db.commit()
        return row

    row.last_error = "; ".join(errors) if errors else "No GeoIP database URL is configured."
    await db.commit()
    raise GeoipDownloadError(row.last_error)


class _ReaderCache:
    """Per-process cache of the built `geoip2.database.Reader` — the
    underlying C extension needs a real file path or descriptor, not a
    bytes buffer (confirmed live: passing a `BytesIO` raises `TypeError:
    expected str, bytes or os.PathLike object`), so the cached database
    bytes are written to a private temp file once per (re)build, not once
    per lookup. Revalidated against `GeoipDatabase.updated_at` at most
    every `_RECHECK_INTERVAL` — see the module docstring."""

    def __init__(self) -> None:
        self._reader: geoip2.database.Reader | None = None
        self._db_updated_at: datetime | None = None
        self._checked_at: datetime | None = None
        self._tmp_path: str | None = None

    async def get(self, db: AsyncSession) -> geoip2.database.Reader | None:
        now = datetime.now(UTC)
        if self._checked_at is not None and now - self._checked_at < _RECHECK_INTERVAL:
            return self._reader
        self._checked_at = now

        row = await db.get(GeoipDatabase, SINGLETON_ID)
        if row is None or row.mmdb_data is None:
            self._reset()
            return None
        if self._reader is not None and row.updated_at == self._db_updated_at:
            return self._reader

        self._reset()
        fd, path = tempfile.mkstemp(suffix=".mmdb", prefix="honeypotshelf-geoip-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(row.mmdb_data)
            self._reader = geoip2.database.Reader(path)
        except Exception:
            logger.exception("Failed to open the downloaded GeoIP database")
            with contextlib.suppress(OSError):
                os.unlink(path)
            return None
        self._tmp_path = path
        self._db_updated_at = row.updated_at
        return self._reader

    def _reset(self) -> None:
        if self._reader is not None:
            with contextlib.suppress(Exception):
                self._reader.close()
        if self._tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(self._tmp_path)
        self._reader = None
        self._tmp_path = None
        self._db_updated_at = None


_cache = _ReaderCache()


async def get_reader(db: AsyncSession) -> geoip2.database.Reader | None:
    """The current cached `Reader`, `None` if GeoIP has never been
    successfully downloaded (not configured yet, or every attempt so far
    has failed)."""
    return await _cache.get(db)


def lookup(reader: geoip2.database.Reader, ip_str: str | None) -> GeoLocation | None:
    """Best-effort city lookup for a single IP against an already-open
    `reader` — see the module docstring for why a private/reserved/
    malformed address is `None`, not an error. Also `None` for a public IP
    MaxMind's database simply has no record for
    (`geoip2.errors.AddressNotFoundError` — common for e.g. freshly
    allocated ranges) or any other lookup failure; never raises."""
    if not ip_str:
        return None
    try:
        parsed = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if not parsed.is_global:
        return None
    try:
        response = reader.city(ip_str)
    except geoip2.errors.AddressNotFoundError:
        return None
    except Exception:
        logger.exception("GeoIP lookup failed for %s", ip_str)
        return None
    if response.country.iso_code is None:
        return None
    return GeoLocation(
        country_code=response.country.iso_code,
        country_name=response.country.name,
        city_name=response.city.name,
        latitude=response.location.latitude,
        longitude=response.location.longitude,
    )


async def resolve(db: AsyncSession, ip_str: str | None) -> GeoLocation | None:
    """`get_reader` + `lookup` in one call — `None` either way when GeoIP
    isn't configured/downloaded yet, or nothing more specific applies."""
    reader = await get_reader(db)
    if reader is None:
        return None
    return lookup(reader, ip_str)
