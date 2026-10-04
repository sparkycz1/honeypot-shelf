"""The ignore list for event sources (`app.db.models.ignored_source`): what
an entry may look like, which entries apply to a honeypot, and keeping
`HoneypotEvent.ignored` in step with the list.

New events are marked when they are ingested
(`app.tasks.jobs._poll_honeypot_canary_log`). When the list changes,
`reapply` goes over the stored events so that adding an entry also quiets
what is already there, and removing one brings it back.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable

from sqlalchemy import CursorResult, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.scope import visible_company_ids
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_event import HoneypotEvent
from app.db.models.ignored_source import IgnoredSource
from app.db.models.user import User

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Wider than this is almost certainly a typo that would silence real
# attackers ("0.0.0.0/0", a /4 instead of a /24).
MIN_IPV4_PREFIX = 8
MIN_IPV6_PREFIX = 32
MAX_NOTE_LENGTH = 255
_UPDATE_CHUNK = 500


def parse_network(value: str) -> str:
    """An address or a CIDR network as its normalised text
    ("203.0.113.7" → "203.0.113.7/32"). Raises ValueError with a message
    for the person typing it."""
    text = value.strip()
    if not text:
        raise ValueError("Enter an address or a network, e.g. 203.0.113.7 or 203.0.113.0/24.")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f'"{text}" is not an IP address or a network in CIDR form.') from None
    minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
    if network.prefixlen < minimum:
        raise ValueError(
            f"{network} is too wide: the shortest prefix allowed is /{minimum}. "
            "Ignoring that much would hide real attackers."
        )
    return str(network)


def matches(src_ip: str | None, networks: Iterable[Network]) -> bool:
    if not src_ip:
        return False
    try:
        address = ipaddress.ip_address(src_ip.strip())
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in networks)


def _as_networks(entries: Iterable[IgnoredSource]) -> list[Network]:
    networks: list[Network] = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.network, strict=False))
        except ValueError:
            continue  # never written by `parse_network`; skip rather than fail an ingest
    return networks


async def networks_for(db: AsyncSession, honeypot: Honeypot) -> list[Network]:
    """Every network ignored for `honeypot`: the entries of each company it
    belongs to, plus the ones that apply everywhere. `honeypot.companies`
    must already be loaded."""
    company_ids = [company.id for company in honeypot.companies]
    result = await db.execute(
        select(IgnoredSource).where(
            or_(IgnoredSource.company_id.is_(None), IgnoredSource.company_id.in_(company_ids))
        )
    )
    return _as_networks(result.scalars().all())


async def entries_visible_to(db: AsyncSession, user: User) -> list[IgnoredSource]:
    """The entries `user` may see: those of their companies and the ones
    that apply everywhere; all of them for a superadmin."""
    query = select(IgnoredSource).order_by(IgnoredSource.network)
    company_ids = visible_company_ids(user)
    if company_ids is not None:
        query = query.where(
            or_(IgnoredSource.company_id.is_(None), IgnoredSource.company_id.in_(company_ids))
        )
    return list((await db.execute(query)).scalars().all())


def can_manage(user: User, company_id: uuid.UUID | None) -> bool:
    """A company's entries: write access to that company. Entries for every
    honeypot: only an account that sees every company."""
    if company_id is None:
        return user.sees_every_company
    return user.can_write_company(company_id)


async def reapply(db: AsyncSession) -> int:
    """Bring `HoneypotEvent.ignored` in line with the list for every stored
    event; returns how many rows changed. Works per honeypot and per
    distinct source address, so its cost follows the number of addresses,
    not the number of events."""
    changed = 0
    honeypots = (
        await db.execute(select(Honeypot).options(selectinload(Honeypot.companies)))
    ).scalars()
    for honeypot in list(honeypots):
        networks = await networks_for(db, honeypot)
        pairs = (
            await db.execute(
                select(HoneypotEvent.src_ip, HoneypotEvent.ignored)
                .where(HoneypotEvent.honeypot_id == honeypot.id, HoneypotEvent.src_ip.is_not(None))
                .distinct()
            )
        ).all()
        to_ignore = [ip for ip, ignored in pairs if not ignored and matches(ip, networks)]
        to_restore = [ip for ip, ignored in pairs if ignored and not matches(ip, networks)]
        for addresses, flag in ((to_ignore, True), (to_restore, False)):
            for start in range(0, len(addresses), _UPDATE_CHUNK):
                chunk = addresses[start : start + _UPDATE_CHUNK]
                result = await db.execute(
                    update(HoneypotEvent)
                    .where(
                        HoneypotEvent.honeypot_id == honeypot.id,
                        HoneypotEvent.src_ip.in_(chunk),
                        HoneypotEvent.ignored.is_(not flag),
                    )
                    .values(ignored=flag)
                )
                if isinstance(result, CursorResult):
                    changed += result.rowcount or 0
    await db.commit()
    return changed
