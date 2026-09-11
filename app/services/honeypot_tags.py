"""Creating/reusing `Tag` rows by name and keeping the table free of
orphans — the only place `app.db.models.honeypot_tag` rows are written.
See that module's own docstring for the data model.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_tag import Tag, honeypot_tags
from app.ssh.opencanary_config import TOGGLEABLE_MODULE_KEYS, enabled_module_tag_names

MAX_TAG_LENGTH = 64

# A comma or a newline (a `<textarea>`-pasted list, or a plain
# comma-separated `<input>`) both split a tag list the same way.
_TAG_SPLIT_RE = re.compile(r"[,\n]+")


def normalize_tag_names(names: list[str]) -> list[str]:
    """Lowercase, trim, cap length, drop blanks, and de-duplicate —
    order-preserving. Used for both the web form's comma-separated text
    and the REST API's JSON array, so "prod" typed twice, in either shape,
    always ends up as the same one tag."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in names:
        name = raw.strip().lower()[:MAX_TAG_LENGTH]
        if name and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def parse_tag_names_from_text(raw: str) -> list[str]:
    """The web form's `<input name="tags">` — a comma/newline-separated
    string — into the same normalized list `normalize_tag_names` produces
    from a JSON array."""
    return normalize_tag_names(_TAG_SPLIT_RE.split(raw))


async def _delete_orphaned_tags(db: AsyncSession, tag_ids: Iterable[uuid.UUID]) -> None:
    for tag_id in tag_ids:
        count = (
            await db.execute(
                select(func.count())
                .select_from(honeypot_tags)
                .where(honeypot_tags.c.tag_id == tag_id)
            )
        ).scalar_one()
        if count == 0:
            tag = await db.get(Tag, tag_id)
            if tag is not None:
                await db.delete(tag)


async def set_honeypot_tags(db: AsyncSession, honeypot: Honeypot, names: list[str]) -> None:
    """Replace `honeypot`'s tags with the ones named in `names` (already
    normalized) — creating any that don't exist yet, and deleting any
    *other* tag left with zero honeypots afterward, so there's never a
    separate "manage tags" page needed just to clean up a rename or a
    typo. `honeypot` must already be persistent (flushed, has an `id`).
    Caller commits.

    Deliberately works at the Core (association-table row) level rather
    than reading/assigning `honeypot.tags` as an ORM collection: on an
    `AsyncSession`, touching an unloaded relationship attribute as plain
    Python (not through `await session.execute(...)`/`refresh(...)`) raises
    `MissingGreenlet` — whether `honeypot` was loaded with `tags` eagerly
    populated already isn't something this function should have to assume
    about its caller.
    """
    previous_result = await db.execute(
        select(honeypot_tags.c.tag_id).where(honeypot_tags.c.honeypot_id == honeypot.id)
    )
    previous_tag_ids = set(previous_result.scalars().all())

    new_tag_ids: set[uuid.UUID] = set()
    if names:
        result = await db.execute(select(Tag).where(Tag.name.in_(names)))
        existing = {tag.name: tag for tag in result.scalars().all()}
        for name in names:
            tag = existing.get(name)
            if tag is None:
                tag = Tag(name=name)
                db.add(tag)
                await db.flush()  # assign an id before it's referenced below
                existing[name] = tag
            new_tag_ids.add(tag.id)

    to_remove = previous_tag_ids - new_tag_ids
    to_add = new_tag_ids - previous_tag_ids

    if to_remove:
        await db.execute(
            honeypot_tags.delete().where(
                honeypot_tags.c.honeypot_id == honeypot.id,
                honeypot_tags.c.tag_id.in_(to_remove),
            )
        )
    for tag_id in to_add:
        await db.execute(honeypot_tags.insert().values(honeypot_id=honeypot.id, tag_id=tag_id))
    await db.flush()

    # A previously-loaded `honeypot.tags` collection (e.g. the object came
    # from a `selectinload`-backed query) would otherwise keep showing the
    # old membership for the rest of this session.
    await db.refresh(honeypot, attribute_names=["tags"])

    await _delete_orphaned_tags(db, to_remove)


async def add_tags_to_honeypots(
    db: AsyncSession, honeypot_ids: list[uuid.UUID], names: list[str]
) -> None:
    """Add `names` (already normalized) to every honeypot in `honeypot_ids`,
    leaving each honeypot's *other* tags untouched — the honeypot list's bulk
    "Add tags" action. Creates any tag that doesn't exist yet. A pair
    that's already there is silently skipped, never a duplicate-row error.
    Caller commits."""
    if not names or not honeypot_ids:
        return

    result = await db.execute(select(Tag).where(Tag.name.in_(names)))
    existing = {tag.name: tag for tag in result.scalars().all()}
    tag_ids: list[uuid.UUID] = []
    for name in names:
        tag = existing.get(name)
        if tag is None:
            tag = Tag(name=name)
            db.add(tag)
            await db.flush()  # assign an id before it's referenced below
            existing[name] = tag
        tag_ids.append(tag.id)

    already_result = await db.execute(
        select(honeypot_tags.c.honeypot_id, honeypot_tags.c.tag_id).where(
            honeypot_tags.c.honeypot_id.in_(honeypot_ids), honeypot_tags.c.tag_id.in_(tag_ids)
        )
    )
    already = set(already_result.all())
    rows = [
        {"honeypot_id": honeypot_id, "tag_id": tag_id}
        for honeypot_id in honeypot_ids
        for tag_id in tag_ids
        if (honeypot_id, tag_id) not in already
    ]
    if rows:
        await db.execute(honeypot_tags.insert(), rows)
    await db.flush()


async def remove_tags_from_honeypots(
    db: AsyncSession, honeypot_ids: list[uuid.UUID], names: list[str]
) -> None:
    """Remove `names` (already normalized) from every honeypot in
    `honeypot_ids`, leaving each honeypot's *other* tags untouched — the
    honeypot list's bulk "Remove tags" action. Deletes any of those tags
    left with zero honeypots afterward, same as `set_honeypot_tags`. Caller
    commits."""
    if not names or not honeypot_ids:
        return

    tag_ids = list((await db.execute(select(Tag.id).where(Tag.name.in_(names)))).scalars().all())
    if not tag_ids:
        return

    await db.execute(
        honeypot_tags.delete().where(
            honeypot_tags.c.honeypot_id.in_(honeypot_ids), honeypot_tags.c.tag_id.in_(tag_ids)
        )
    )
    await db.flush()
    await _delete_orphaned_tags(db, tag_ids)


async def sync_module_tags(db: AsyncSession, honeypot: Honeypot, config: dict[str, Any]) -> None:
    """Called after every successful OpenCanary module-config save
    (`app.web.routes.honeypots.save_honeypot_opencanary_config_endpoint`)
    — tags the honeypot with exactly its currently-enabled modules
    (`ftp`, `http`, `ssh`, ...) and untags whichever module tags no longer
    apply, per explicit request: "auto-tag by enabled service, untag what
    got turned off, but never touch a manually-added tag."

    Works by set difference against `TOGGLEABLE_MODULE_KEYS` — the full,
    fixed vocabulary of tag names this function is allowed to own —
    rather than simply overwriting `honeypot.tags` with the enabled-module
    list (`set_honeypot_tags` *replaces* the whole tag set, which would
    silently wipe any tag an operator added by hand): a tag outside that
    vocabulary is by definition never something this function put there,
    so it's left alone regardless of what's enabled/disabled this time.
    """
    current_result = await db.execute(
        select(Tag.name)
        .select_from(honeypot_tags)
        .join(Tag, Tag.id == honeypot_tags.c.tag_id)
        .where(honeypot_tags.c.honeypot_id == honeypot.id)
    )
    current_names = set(current_result.scalars().all())
    manual_names = current_names - TOGGLEABLE_MODULE_KEYS

    enabled_names = set(enabled_module_tag_names(config))
    new_names = manual_names | enabled_names
    if new_names == current_names:
        return  # nothing to change — avoid a pointless write/refresh

    await set_honeypot_tags(db, honeypot, sorted(new_names))
