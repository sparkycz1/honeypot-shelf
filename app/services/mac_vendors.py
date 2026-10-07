"""The list of MAC address prefixes and their manufacturers: downloading
it, searching it, and making up an address that belongs to one of them.

A honeypot can be given a MAC address so it looks like a particular
maker's device on its network (`app.ssh.mac_address`). Typing one in
always works; picking a manufacturer needs this list, which is not
shipped with the app — a superadmin points Settings -> Integrations at one
and says how often to fetch it again.

**Format**: one prefix per line, `000C29<TAB>VMware, Inc.` — six hex
digits (also accepted as `00:0C:29` or `00-0C-29`), whitespace, the name.
Blank lines and lines starting with `#` are skipped, as is anything that
does not start with a prefix, so a file with a heading or commentary
still loads.

**Fetching** is guarded like a webhook target (`app.services.webhook`):
plain http(s) to a public address only, size-capped, and a download that
yields too few prefixes to be a real list replaces nothing.
"""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta

import httpx2
from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.mac_vendor import MacVendor
from app.services.webhook import UnsafeWebhookTargetError, validate_webhook_url

DEFAULT_REFRESH_INTERVAL_HOURS = 168
MAX_URL_LENGTH = 1000
_DOWNLOAD_TIMEOUT_SECONDS = 30.0
_MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
_MAX_ENTRIES = 200_000
# Fewer prefixes than this is an error page or the wrong file, not a list.
_MIN_ENTRIES = 10
_INSERT_BATCH = 2000
SEARCH_LIMIT = 15

_LINE_RE = re.compile(
    r"^\s*([0-9A-Fa-f]{2})[:\-.]?([0-9A-Fa-f]{2})[:\-.]?([0-9A-Fa-f]{2})\s+(\S.*?)\s*$"
)


class MacVendorListError(Exception):
    """The list could not be downloaded or is not a list — the message is
    shown on the Settings page."""


def parse_vendor_list(text: str) -> dict[str, str]:
    """`{"000C29": "VMware, Inc.", ...}` — see the module docstring for the
    format. A prefix listed twice keeps its last name."""
    vendors: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _LINE_RE.match(line)
        if match is None:
            continue
        oui = (match.group(1) + match.group(2) + match.group(3)).upper()
        vendors[oui] = match.group(4)[:255]
        if len(vendors) > _MAX_ENTRIES:
            raise MacVendorListError(f"The list has more than {_MAX_ENTRIES} prefixes.")
    return vendors


def validate_list_url(url: str) -> None:
    if len(url) > MAX_URL_LENGTH:
        raise MacVendorListError("The list address is too long.")
    try:
        validate_webhook_url(url)
    except UnsafeWebhookTargetError as exc:
        raise MacVendorListError(
            "The list address must be a public http:// or https:// address."
        ) from exc


async def _download(url: str) -> str:
    validate_list_url(url)
    try:
        async with (
            httpx2.AsyncClient(timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client,
            client.stream("GET", url) as response,
        ):
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > _MAX_DOWNLOAD_BYTES:
                    raise MacVendorListError("The list is larger than 10 MB.")
                chunks.append(chunk)
    except httpx2.HTTPError as exc:
        raise MacVendorListError(f"Could not download the list: {exc}") from exc
    return b"".join(chunks).decode("utf-8", errors="replace")


async def refresh_vendor_list(db: AsyncSession, app_settings: AppSettings) -> int:
    """Download the configured list and replace the stored one with it.
    Returns how many prefixes it has. On any failure the stored list is
    left exactly as it was and the reason is recorded on `app_settings`
    (and raised)."""
    app_settings.mac_vendor_list_attempted_at = datetime.now(UTC)
    url = (app_settings.mac_vendor_list_url or "").strip()
    try:
        if not url:
            raise MacVendorListError("No list address is set.")
        vendors = parse_vendor_list(await _download(url))
        if len(vendors) < _MIN_ENTRIES:
            raise MacVendorListError(
                "The address did not return a list of MAC prefixes "
                "(expected lines like “000C29<TAB>VMware, Inc.”)."
            )
    except MacVendorListError as exc:
        app_settings.mac_vendor_list_error = str(exc)
        await db.commit()
        raise

    await db.execute(delete(MacVendor))
    rows = [{"oui": oui, "vendor": vendor} for oui, vendor in vendors.items()]
    for start in range(0, len(rows), _INSERT_BATCH):
        await db.execute(insert(MacVendor), rows[start : start + _INSERT_BATCH])
    app_settings.mac_vendor_list_updated_at = app_settings.mac_vendor_list_attempted_at
    app_settings.mac_vendor_list_error = None
    await db.commit()
    return len(rows)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_due(app_settings: AppSettings, *, now: datetime | None = None) -> bool:
    """Whether the periodic job should fetch the list now: an address is
    set, and the last attempt — successful or not — is at least one
    refresh interval old."""
    if not (app_settings.mac_vendor_list_url or "").strip():
        return False
    attempted = app_settings.mac_vendor_list_attempted_at
    if attempted is None:
        return True
    interval = timedelta(hours=max(app_settings.mac_vendor_refresh_interval_hours, 1))
    return (now or datetime.now(UTC)) - _aware(attempted) >= interval


async def vendor_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(MacVendor))).scalar_one()


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def search_vendors(db: AsyncSession, query: str) -> list[tuple[str, int]]:
    """Manufacturers whose name contains `query`: (name, how many prefixes
    it has), the ones with most prefixes first — the big, plausible makers
    before the one-off registrations."""
    query = query.strip()
    if len(query) < 2:
        return []
    prefixes = func.count().label("prefixes")
    result = await db.execute(
        select(MacVendor.vendor, prefixes)
        .where(MacVendor.vendor.ilike(_like(query), escape="\\"))
        .group_by(MacVendor.vendor)
        .order_by(prefixes.desc(), MacVendor.vendor)
        .limit(SEARCH_LIMIT)
    )
    return [(name, count) for name, count in result.all()]


async def generate_address(db: AsyncSession, vendor: str) -> str | None:
    """A MAC address of `vendor`: one of its prefixes, the rest random.
    None when the list has no such manufacturer. Skips a prefix that could
    not be an interface's address (multicast bit set) — the list has a
    few historical ones."""
    result = await db.execute(select(MacVendor.oui).where(MacVendor.vendor == vendor))
    usable = [oui for oui in result.scalars().all() if not int(oui[:2], 16) & 1]
    if not usable:
        return None
    oui = secrets.choice(usable).lower()
    tail = secrets.token_hex(3)
    digits = oui + tail
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


async def vendor_of(db: AsyncSession, mac: str) -> str | None:
    """The manufacturer `mac`'s prefix belongs to, if the list knows it."""
    oui = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
    if len(oui) != 6:
        return None
    return (
        await db.execute(select(MacVendor.vendor).where(MacVendor.oui == oui))
    ).scalar_one_or_none()
