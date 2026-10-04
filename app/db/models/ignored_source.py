"""Source addresses whose events are expected and should stay quiet — a
vulnerability scanner, a monitoring probe, the admin's own workstation.

An entry is a single address or a network (CIDR), with a note saying what
it is. It belongs to one company (it then applies to that company's
honeypots) or, with `company_id` NULL, to every honeypot — only a
superadmin can make those.

An event from a matching address is still stored, marked
`HoneypotEvent.ignored`: it sends no notification and is left out of the
Dashboard, the Activity tab's charts, the map and the daily totals, but
can still be found on the Events page ("Include ignored"). See
`app.services.ignored_sources`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IgnoredSource(Base):
    __tablename__ = "ignored_sources"
    __table_args__ = (
        UniqueConstraint("company_id", "network", name="uq_ignored_source_company_network"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # NULL = every honeypot, whatever its companies.
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=True, index=True
    )
    company: Mapped[Company | None] = relationship(lazy="joined")
    # Normalised by `ipaddress.ip_network`: "203.0.113.7/32", "10.0.0.0/8",
    # "2001:db8::/32".
    network: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"IgnoredSource(network={self.network!r}, company_id={self.company_id!r})"


# Imported last, and only for type checking — see app.db.models.api_token.
if TYPE_CHECKING:
    from app.db.models.company import Company
