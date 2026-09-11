"""A `User`'s access to one `Company`, with its own `AccessLevel`.

Replaces the old `User.company_id`/`User.access_level` (a required single
FK + enum pair) — a non-superadmin user can now hold any number of these,
including zero (locked out of every company until one is granted), one
per row in `access_level` independently. Superadmins never have one (they
see everything regardless — see `app.db.models.user`).

A plain per-(user, company) row rather than a bare many-to-many table
(unlike `honeypot_companies`) because it carries data of its own —
`access_level` — so it needs to be a real model, not just a `secondary=`
link table.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.user import AccessLevel
from app.db.pg_enum import pg_enum

if TYPE_CHECKING:
    from app.db.models.company import Company
    from app.db.models.user import User


class CompanyMembership(Base):
    __tablename__ = "company_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "company_id", name="uq_company_membership_user_company"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    company_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("companies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    access_level: Mapped[AccessLevel] = mapped_column(
        pg_enum(AccessLevel, name="access_level"), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="memberships")
    company: Mapped[Company] = relationship(back_populates="memberships", lazy="joined")

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"CompanyMembership(user_id={self.user_id!r}, company_id={self.company_id!r}, "
            f"access_level={self.access_level!r})"
        )
