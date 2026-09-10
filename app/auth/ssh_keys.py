"""Parsing/validation for a user's personal SSH public key(s)
(`User.ssh_public_keys`, My account → SSH public keys). See
`app.ssh.authorized_keys` for how these are actually deployed onto a
honeypot, and `app.web.routes.initialize_ws`/`app.tasks.jobs.
push_superadmin_ssh_keys` for the two places that read them.
"""

from __future__ import annotations

import asyncssh


class InvalidSshPublicKeyError(ValueError):
    """One line of pasted input isn't a well-formed SSH public key."""


def parse_ssh_public_keys(raw: str) -> list[str]:
    """One validated, `authorized_keys`-ready line per entry. Blank lines
    and `#`-prefixed comments are silently dropped (the same way an actual
    `authorized_keys` file treats them) — everything else must parse as a
    real public key via `asyncssh.import_public_key`, or this raises
    `InvalidSshPublicKeyError` naming the offending line, rather than
    silently dropping something the caller likely meant to paste
    correctly. Never partially accepts an input — raises before returning
    anything if any line is bad, so a typo in the third of five keys can't
    silently save only the first two."""
    keys: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            asyncssh.import_public_key(stripped)
        except asyncssh.KeyImportError as exc:
            shown = stripped if len(stripped) <= 60 else stripped[:57] + "..."
            raise InvalidSshPublicKeyError(f"Not a valid SSH public key: {shown}") from exc
        keys.append(stripped)
    return keys
