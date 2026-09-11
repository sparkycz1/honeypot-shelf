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

from sqlalchemy import Boolean, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum
from app.services.syslog_transport import DEFAULT_SYSLOG_PORT, SyslogProtocol

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

    # --- Per-company syslog forwarding of this company's own honeypot
    # *alerts* only (app.services.honeypot_event_syslog) — deliberately
    # separate from AppSettings.syslog_* (app.audit_syslog), which is
    # global and carries audit log entries, never honeypot alerts. Lets a
    # multi-tenant deployment route each company's own alert traffic to
    # that company's own SIEM/syslog server, rather than one shared
    # target for the whole fleet. Same shape/transport
    # (app.services.syslog_transport) as the global target, just scoped
    # to one company and to alerts instead of audit entries. ---
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    syslog_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SYSLOG_PORT, nullable=False)
    syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        pg_enum(SyslogProtocol, name="syslog_protocol"),
        default=SyslogProtocol.UDP,
        nullable=False,
    )

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
