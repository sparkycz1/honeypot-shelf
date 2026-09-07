"""One installed package on a managed honeypot, as of the last package
refresh — see `app.ssh.packages` for how it's gathered and
`app.tasks.jobs.refresh_honeypot_packages` for how it's kept in sync.

Each refresh replaces a honeypot's whole set of rows in one transaction
(delete-then-bulk-insert) rather than diffing — it's a snapshot of "what's
installed right now," not a history of package changes.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum
from app.ssh.packages import PackageSource

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot


class HoneypotPackage(Base):
    __tablename__ = "honeypot_packages"
    __table_args__ = (
        Index("ix_honeypot_packages_honeypot_id_source", "honeypot_id", "source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # One-directional — Honeypot deliberately has no `packages` relationship
    # back (a honeypot's package list can run into the thousands, and every
    # place that needs it already queries HoneypotPackage directly rather
    # than eager-loading through Honeypot). Used by the fleet-wide package
    # search, which needs each hit's honeypot name/id.
    honeypot: Mapped[Honeypot] = relationship(viewonly=True)

    source: Mapped[PackageSource] = mapped_column(
        pg_enum(PackageSource, name="package_source"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    # apt-only ("apt-mark showhold") — always False for flatpak/snap, which
    # have no equivalent concept.
    held: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"HoneypotPackage(honeypot_id={self.honeypot_id!r}, source={self.source!r}, "
            f"name={self.name!r})"
        )
