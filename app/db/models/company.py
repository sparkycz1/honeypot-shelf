"""A company (tenant). Replaces debcontrol's `MachineGroup` as the one
scoping unit in HoneyHive — every `Honeypot` belongs to exactly one
`Company`, and every `User` belongs to exactly one `Company` (see
`app.db.models.user`). There is deliberately no nesting and no
many-to-many: one honeypot, one company; one user, one company. A
superadmin account (`User.is_superadmin`) is the only thing that spans
more than one.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.honeypot import Honeypot
    from app.db.models.user import User


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Free-text, shown on the company's own page — site/contact notes, not
    # structured data.
    notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    users: Mapped[list[User]] = relationship(back_populates="company")
    honeypots: Mapped[list[Honeypot]] = relationship(
        back_populates="company", cascade="all, delete-orphan"
    )

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Company(id={self.id!r}, name={self.name!r})"
