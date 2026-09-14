"""`app.services.geoip` — download/fallback/validation logic, and the
private-IP-skip guard on the read side. Deliberately doesn't exercise a
real MaxMind database (no writer library available to build a throwaway
one, and shipping a real GeoLite2 file isn't allowed under its license) —
`_fetch_and_validate` is monkeypatched instead, same as every other
external-service call in this suite (see `tests/conftest.py`)."""

from __future__ import annotations

import gzip
import io
import tarfile

import pytest

from app.core.app_settings import get_or_create_app_settings
from app.core.security import encrypt_secret
from app.services.geoip import (
    GeoipDownloadError,
    _extract_mmdb,
    lookup,
    refresh_geoip_database,
)

pytestmark = pytest.mark.asyncio


def test_extract_mmdb_returns_raw_bytes_unchanged():
    assert _extract_mmdb(b"not-really-an-mmdb") == b"not-really-an-mmdb"


def test_extract_mmdb_decompresses_a_plain_gzip():
    payload = b"fake mmdb bytes"
    gzipped = gzip.compress(payload)
    assert _extract_mmdb(gzipped) == payload


def test_extract_mmdb_extracts_the_mmdb_member_from_a_tar():
    payload = b"fake mmdb bytes inside a tar"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="GeoLite2-City_20260101/GeoLite2-City.mmdb")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
        # A sibling file that isn't the .mmdb - must be ignored, not picked
        # up instead (MaxMind's own tarballs also include a COPYRIGHT.txt/
        # LICENSE.txt alongside the real file).
        other = tarfile.TarInfo(name="GeoLite2-City_20260101/LICENSE.txt")
        other.size = 4
        tar.addfile(other, io.BytesIO(b"text"))
    assert _extract_mmdb(buf.getvalue()) == payload


def test_extract_mmdb_gzipped_tar_extracts_the_mmdb_member():
    payload = b"fake mmdb bytes"
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        info = tarfile.TarInfo(name="dir/GeoLite2-City.mmdb")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    assert _extract_mmdb(gzip.compress(tar_buf.getvalue())) == payload


def test_extract_mmdb_raises_when_tar_has_no_mmdb_member():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name="dir/README.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"text"))
    with pytest.raises(GeoipDownloadError):
        _extract_mmdb(buf.getvalue())


def test_lookup_skips_a_private_address_without_touching_the_reader():
    """The private-IP guard runs before the reader is ever consulted - a
    reader that would raise on any real call (`None` here) proves the
    guard short-circuits first, not just that it happens to also return
    None for a bogus reader."""
    assert lookup(None, "192.168.1.1") is None  # type: ignore[arg-type]
    assert lookup(None, "10.0.0.5") is None  # type: ignore[arg-type]
    assert lookup(None, "127.0.0.1") is None  # type: ignore[arg-type]
    assert lookup(None, "::1") is None  # type: ignore[arg-type]


def test_lookup_returns_none_for_a_malformed_address():
    assert lookup(None, "not-an-ip") is None  # type: ignore[arg-type]
    assert lookup(None, None) is None  # type: ignore[arg-type]
    assert lookup(None, "") is None  # type: ignore[arg-type]


async def test_refresh_falls_back_to_backup_url_when_primary_fails(
    db_session_factory, monkeypatch
):
    async def fake_fetch(url: str) -> bytes:
        if url == "https://primary.example/db":
            raise RuntimeError("primary is down")
        assert url == "https://backup.example/db"
        return b"backup-bytes"

    monkeypatch.setattr("app.services.geoip._fetch_and_validate", fake_fetch)

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_primary_url_encrypted = encrypt_secret("https://primary.example/db")
        app_settings.geoip_backup_url_encrypted = encrypt_secret("https://backup.example/db")
        await db.commit()

        row = await refresh_geoip_database(db, app_settings)
        assert row.source == "backup"
        assert row.mmdb_data == b"backup-bytes"
        assert row.last_error is None
        assert row.updated_at is not None


async def test_refresh_never_tries_backup_when_primary_succeeds(db_session_factory, monkeypatch):
    calls: list[str] = []

    async def fake_fetch(url: str) -> bytes:
        calls.append(url)
        return b"primary-bytes"

    monkeypatch.setattr("app.services.geoip._fetch_and_validate", fake_fetch)

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_primary_url_encrypted = encrypt_secret("https://primary.example/db")
        app_settings.geoip_backup_url_encrypted = encrypt_secret("https://backup.example/db")
        await db.commit()

        row = await refresh_geoip_database(db, app_settings)
        assert row.source == "primary"
        assert calls == ["https://primary.example/db"]


async def test_refresh_raises_and_records_error_when_every_url_fails(
    db_session_factory, monkeypatch
):
    async def fake_fetch(url: str) -> bytes:
        raise RuntimeError(f"{url} is unreachable")

    monkeypatch.setattr("app.services.geoip._fetch_and_validate", fake_fetch)

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.geoip_primary_url_encrypted = encrypt_secret("https://primary.example/db")
        app_settings.geoip_backup_url_encrypted = encrypt_secret("https://backup.example/db")
        await db.commit()

        with pytest.raises(GeoipDownloadError):
            await refresh_geoip_database(db, app_settings)

        from app.db.models.geoip_database import SINGLETON_ID, GeoipDatabase

        row = await db.get(GeoipDatabase, SINGLETON_ID)
        assert row is not None
        assert row.mmdb_data is None
        assert row.last_error is not None
        assert "primary" in row.last_error and "backup" in row.last_error
        assert row.last_attempted_at is not None


async def test_refresh_raises_when_no_url_is_configured(db_session_factory):
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        with pytest.raises(GeoipDownloadError):
            await refresh_geoip_database(db, app_settings)
