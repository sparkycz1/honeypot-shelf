"""Watching chosen files on a honeypot for changes. Ported from debcontrol.

Each honeypot has a list of paths (`HoneypotWatchedFile`). Every facts
refresh reads them over SSH; the first reading is the baseline, and any
later difference is written to the audit log against the honeypot (so it
shows on its History tab), sent to the notification rules that asked for
"a watched file changed", and kept as a diff against the version before.

**A default list.** A honeypot nobody has edited the list of
(`Honeypot.watched_files_customized` false) watches `DEFAULT_PATHS` plus
the management account's own `authorized_keys` — the files an intruder
who got past the decoy would most likely touch. Saving the list once, even
empty, ends that for the honeypot.

**Read as root.** Unlike debcontrol, the files are read through the same
temp-script-then-`sudo -n bash` shape every other privileged action here
uses (`app.ssh.opencanary_config.build_write_command`) — the onboarding
sudoers rule already allows `bash /tmp/.honeypotshelf-*`, so nothing is
added to it, and root-only files (`/etc/sudoers`, `/root/.ssh/...`) can be
watched. Without that grant (or connected as root already) the script
simply runs as the login account.

**What is stored and who sees it.** The current and the previous content
of each file, encrypted like every other secret in this app — a
configuration file can hold a password. The diff and the list of paths
are for accounts that may write the honeypot; a notification and the
History say *which* file changed and by how many lines, never what the
lines are.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import re
import shlex
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.honeypot import Honeypot
from app.db.models.honeypot_watched_file import HoneypotWatchedFile

MAX_FILES = 20
MAX_BYTES = 65536

STATE_PENDING = "pending"
STATE_OK = "ok"
STATE_MISSING = "missing"
STATE_UNREADABLE = "unreadable"
STATE_TOO_LARGE = "too_large"
_STATES = (STATE_OK, STATE_MISSING, STATE_UNREADABLE, STATE_TOO_LARGE)

# Watched on every honeypot whose list nobody has edited yet, together with
# the management account's own `~/.ssh/authorized_keys`
# (`default_paths`): the decoy's own configuration, who may log in and how,
# and who may become root.
DEFAULT_PATHS = (
    "/etc/opencanaryd/opencanary.conf",
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
)

_PATH_RE = re.compile(r"^/[A-Za-z0-9_./@+-]{1,500}$")
_MARKER_RE = re.compile(r"^===FILE (\d{1,3}) (\w{1,16})===$")
# A home directory as `getent passwd` reports it (`app.tasks.jobs`).
_HOME_RE = re.compile(r"^/[A-Za-z0-9_./@+-]{0,200}$")

# Written by the login account, then run once under `sudo -n bash` — the
# name matches the onboarding sudoers rule's `/tmp/.honeypotshelf-*`.
_SCRIPT_TEMPLATE = "/tmp/.honeypotshelf-watch-XXXXXXXX"  # noqa: S108 - mktemp, removed after
_SCRIPT_MARKER = "HONEYPOTSHELF_WATCHED_FILES"


class WatchedFilesError(ValueError):
    """What is wrong with a list of paths — text for the person who typed it."""


def is_usable_path(path: str) -> bool:
    return bool(_PATH_RE.match(path)) and ".." not in path.split("/") and not path.endswith("/")


def parse_paths(text: str) -> list[str]:
    """Paths from the form: one per line, absolute, made of plain
    characters, no `..`; duplicates dropped, order kept."""
    paths: list[str] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        path = raw.strip()
        if not path:
            continue
        if not is_usable_path(path):
            raise WatchedFilesError(
                f'"{path[:80]}" is not usable: give the full path of a file, made of letters, '
                "digits and _ . / @ + - only."
            )
        if path not in paths:
            paths.append(path)
    if len(paths) > MAX_FILES:
        raise WatchedFilesError(f"At most {MAX_FILES} files can be watched on one honeypot.")
    return paths


def default_paths(home: str | None) -> list[str]:
    """`DEFAULT_PATHS`, plus `<home>/.ssh/authorized_keys` of the account
    Honeypot Shelf logs in as when its home directory is known (and is not
    root's, already in the list)."""
    paths = list(DEFAULT_PATHS)
    if home and _HOME_RE.match(home) and ".." not in home.split("/"):
        keys = home.rstrip("/") + "/.ssh/authorized_keys"
        if is_usable_path(keys) and keys not in paths:
            paths.append(keys)
    return paths


def home_lookup_command(username: str) -> str:
    """The login account's home directory — `getent`, never `~`, which
    under `sudo` would name root's (see CLAUDE.md)."""
    return f"getent passwd {shlex.quote(username)} | cut -d: -f6"


async def list_files(db: AsyncSession, honeypot_id: uuid.UUID) -> list[HoneypotWatchedFile]:
    result = await db.execute(
        select(HoneypotWatchedFile)
        .where(HoneypotWatchedFile.honeypot_id == honeypot_id)
        .order_by(HoneypotWatchedFile.path)
    )
    return list(result.scalars().all())


def needs_defaults(honeypot: Honeypot, rows: list[HoneypotWatchedFile]) -> bool:
    return not honeypot.watched_files_customized and not rows


async def set_paths(
    db: AsyncSession, honeypot: Honeypot, paths: list[str], *, by_person: bool = True
) -> tuple[int, int]:
    """Make `paths` the honeypot's watched files: new ones are added (to be
    read at the next check), dropped ones are deleted with what was stored
    of them. A person saving the list marks it as theirs, so the default
    list is never put back. Commits. Returns (added, removed)."""
    existing = {row.path: row for row in await list_files(db, honeypot.id)}
    added = [path for path in paths if path not in existing]
    removed = [row for path, row in existing.items() if path not in paths]
    for row in removed:
        await db.delete(row)
    db.add_all(HoneypotWatchedFile(honeypot_id=honeypot.id, path=path) for path in added)
    if by_person:
        honeypot.watched_files_customized = True
    await db.commit()
    return len(added), len(removed)


def build_read_script(paths: list[str]) -> str:
    """The script reading every file: a `===FILE <n> <state>===` line per
    path, followed for a readable one by its content in base64. Always
    exits 0, so the plain-account fallback in `build_command` runs only
    when `sudo` itself refused."""
    parts = []
    for index, path in enumerate(paths):
        if not is_usable_path(path):
            raise ValueError("Unusable path.")
        quoted = shlex.quote(path)
        parts.append(
            f"if [ ! -f {quoted} ]; then echo '===FILE {index} missing==='; "
            f"elif [ ! -r {quoted} ]; then echo '===FILE {index} unreadable==='; "
            f'elif [ "$(wc -c < {quoted})" -gt {MAX_BYTES} ]; then '
            f"echo '===FILE {index} too_large==='; "
            f"else echo '===FILE {index} ok==='; base64 < {quoted} | tr -d '\\n'; echo; fi"
        )
    return "\n".join([*parts, "exit 0"]) + "\n"


def build_command(paths: list[str]) -> str:
    """One round trip: write the read script to a fresh `mktemp` file, run
    it as root through the onboarding sudoers grant (or as the login
    account when that is refused), remove it."""
    script = build_read_script(paths)
    return (
        f"f=$(mktemp {_SCRIPT_TEMPLATE}) || exit 1; "
        f"cat > \"$f\" <<'{_SCRIPT_MARKER}'\n{script}{_SCRIPT_MARKER}\n"
        'sudo -n bash "$f" 2>/dev/null || bash "$f"; status=$?; rm -f "$f"; exit $status'
    )


def parse_output(raw: str, count: int) -> dict[int, tuple[str, str | None]]:
    """`{index: (state, content or None)}` for the files that reported.
    Content that is not text (or not valid base64) counts as unreadable.
    When both the `sudo` run and the fallback printed a reading for the
    same file, the last one wins."""
    found: dict[int, tuple[str, str | None]] = {}
    lines = raw.splitlines()
    for position, line in enumerate(lines):
        marker = _MARKER_RE.match(line.strip())
        if marker is None:
            continue
        index, state = int(marker.group(1)), marker.group(2)
        if index >= count or state not in _STATES:
            continue
        if state != STATE_OK:
            found[index] = (state, None)
            continue
        encoded = lines[position + 1].strip() if position + 1 < len(lines) else ""
        if _MARKER_RE.match(encoded):
            encoded = ""
        try:
            content = base64.b64decode(encoded, validate=True).decode("utf-8")
        except binascii.Error, UnicodeDecodeError, ValueError:
            found[index] = (STATE_UNREADABLE, None)
            continue
        found[index] = (STATE_OK, content.replace("\x00", ""))
    return found


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def line_counts(before: str, after: str) -> tuple[int, int]:
    """(lines added, lines removed) between two versions."""
    added = removed = 0
    for line in difflib.ndiff(before.splitlines(), after.splitlines()):
        if line.startswith("+ "):
            added += 1
        elif line.startswith("- "):
            removed += 1
    return added, removed


@dataclass(frozen=True)
class Change:
    path: str
    summary: str


def apply_reading(
    row: HoneypotWatchedFile, state: str, content: str | None, now: datetime
) -> Change | None:
    """Update `row` from one reading. Returns the change worth telling
    someone about, or None (the first reading, or nothing different)."""
    was_state, was_digest = row.state, row.sha256
    row.checked_at = now
    row.state = state
    if state != STATE_OK or content is None:
        if was_state == STATE_OK:
            row.changed_at = now
            return Change(row.path, {"missing": "the file is gone"}.get(state, state))
        return None
    digest = _digest(content)
    if was_digest == digest:
        return None
    previous = decrypt_secret(row.content_encrypted) if row.content_encrypted else None
    row.sha256 = digest
    row.content_encrypted = encrypt_secret(content)
    if previous is None:
        if was_state == STATE_MISSING:
            # Not there before, there now: an `authorized_keys` that
            # appeared is exactly what this is for.
            row.previous_content_encrypted = encrypt_secret("")
            row.lines_added, row.lines_removed = line_counts("", content)
            row.changed_at = now
            return Change(row.path, f"the file appeared, {row.lines_added} lines")
        # The baseline: nothing to compare with yet.
        return None
    row.previous_content_encrypted = encrypt_secret(previous)
    row.lines_added, row.lines_removed = line_counts(previous, content)
    row.changed_at = now
    return Change(row.path, f"+{row.lines_added} / -{row.lines_removed} lines")


def diff_of(row: HoneypotWatchedFile) -> list[str]:
    """The last change of `row` as unified-diff lines; empty when there
    has not been one."""
    if not row.content_encrypted or row.previous_content_encrypted is None:
        return []
    before = decrypt_secret(row.previous_content_encrypted).splitlines()
    after = decrypt_secret(row.content_encrypted).splitlines()
    return list(difflib.unified_diff(before, after, "before", "now", lineterm="", n=3))


def as_dict(row: HoneypotWatchedFile) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "path": row.path,
        "state": row.state,
        "sha256": row.sha256,
        "checked_at": row.checked_at.isoformat() if row.checked_at else None,
        "changed_at": row.changed_at.isoformat() if row.changed_at else None,
        "lines_added": row.lines_added,
        "lines_removed": row.lines_removed,
    }
