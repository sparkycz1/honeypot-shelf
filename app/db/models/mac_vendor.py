"""One row per MAC address prefix (OUI) and the manufacturer it is
assigned to — the downloaded list a honeypot's MAC address can be picked
from (Settings -> Integrations says where it comes from and how often it
is refreshed; `app.services.mac_vendors` downloads and searches it).

Replaced as a whole on every successful download, never edited by hand.
"""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MacVendor(Base):
    __tablename__ = "mac_vendors"

    # The first three bytes of an address, six upper-case hex digits.
    oui: Mapped[str] = mapped_column(String(6), primary_key=True)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
