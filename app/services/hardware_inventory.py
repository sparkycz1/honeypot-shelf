"""Hardware inventory and warranties.

What a physical honeypot is — vendor, model, serial number — is read
with the facts (`app.ssh.hardware`: DMI on a PC, the device tree on a
Raspberry Pi); when it was bought and until when its warranty runs is
typed in by a person. Together they answer "which boxes at which customer
run out of warranty this year". Ported from debcontrol.

None of it applies to a virtual machine: its "hardware" is its
hypervisor's, and it is shown nowhere for a honeypot known to be virtual
(`Honeypot.is_physical` is False). One that could not be classified is
treated as possibly physical.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.scope import honeypots_visible_to
from app.db.models.honeypot import Honeypot
from app.db.models.user import User

# Mark a warranty this close to its end on the pages (a notification
# rule picks its own number of days).
WARRANTY_SOON_DAYS = 60
_MAX_LISTED = 2000


class AssetError(ValueError):
    """A date that cannot be right — text for the person who typed it, and
    a short `code` the web page translates ("date", "year", "order")."""

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def applies(honeypot: Any) -> bool:
    """Whether hardware and warranty are a thing for this honeypot."""
    return honeypot.is_physical is not False


def serial_of(honeypot: Any) -> str | None:
    """The serial to show: the one typed in wins over the firmware's."""
    serial: str | None = honeypot.asset_serial or honeypot.hw_serial
    return serial


def warranty_days_left(honeypot: Any, today: date | None = None) -> int | None:
    """Days until the warranty ends (negative once it has); None when no
    end is recorded or the honeypot is virtual."""
    if not applies(honeypot) or honeypot.warranty_until is None:
        return None
    return int((honeypot.warranty_until - (today or datetime.now().date())).days)


def parse_date(value: str, label: str) -> date | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise AssetError(f"{label}: use a date like 2027-03-31.", "date") from exc
    if not 1990 <= parsed.year <= 2100:
        raise AssetError(f"{label}: the year looks wrong.", "year")
    return parsed


def apply_asset(
    honeypot: Honeypot,
    *,
    purchase_date: date | None,
    warranty_until: date | None,
    asset_serial: str,
    asset_note: str,
) -> None:
    """Set what a person records about the honeypot's hardware."""
    if purchase_date and warranty_until and warranty_until < purchase_date:
        raise AssetError("The warranty cannot end before the purchase.", "order")
    honeypot.purchase_date = purchase_date
    honeypot.warranty_until = warranty_until
    honeypot.asset_serial = " ".join(asset_serial.split())[:128] or None
    honeypot.asset_note = " ".join(asset_note.split())[:255] or None


@dataclass(frozen=True)
class InventoryRow:
    honeypot: Honeypot
    days_left: int | None

    @property
    def state(self) -> str:
        """ "expired" / "soon" / "ok" / "unknown"."""
        if self.days_left is None:
            return "unknown"
        if self.days_left < 0:
            return "expired"
        return "soon" if self.days_left <= WARRANTY_SOON_DAYS else "ok"


def as_dict(honeypot: Any) -> dict[str, Any] | None:
    """The hardware record for the API; None for a virtual honeypot."""
    if not applies(honeypot):
        return None
    return {
        "vendor": honeypot.hw_vendor,
        "model": honeypot.hw_model,
        "serial": serial_of(honeypot),
        "firmware_serial": honeypot.hw_serial,
        "purchase_date": honeypot.purchase_date.isoformat() if honeypot.purchase_date else None,
        "warranty_until": honeypot.warranty_until.isoformat() if honeypot.warranty_until else None,
        "warranty_days_left": warranty_days_left(honeypot),
        "note": honeypot.asset_note,
    }


async def inventory(db: AsyncSession, user: User) -> list[InventoryRow]:
    """Every honeypot that is not known to be virtual, among those `user`
    may see — the ones whose warranty ends soonest first, the ones with no
    end recorded last."""
    result = await db.execute(
        honeypots_visible_to(user)
        .where(Honeypot.is_physical.is_not(False))
        .order_by(Honeypot.name)
        .limit(_MAX_LISTED)
    )
    today = datetime.now().date()
    rows = [InventoryRow(h, warranty_days_left(h, today)) for h in result.scalars().all()]
    rows.sort(key=lambda r: (r.days_left is None, r.days_left or 0, r.honeypot.name.lower()))
    return rows
