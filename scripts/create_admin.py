#!/usr/bin/env python3
"""Bootstrap the very first superadmin account.

Every HoneyHive account is created inside the app itself (see
`app/db/models/user.py` — no auto-provisioning from LDAP/OIDC), and every
page requires a login (see `app.auth.middleware`) — so a fresh deployment
needs one way in that isn't a web page. This is it.

Usage (inside the running `web` container):
    docker compose exec web python scripts/create_admin.py --username admin

Prompts for a password interactively. For non-interactive/scripted use, set
`HONEYHIVE_ADMIN_PASSWORD` in the environment instead of a `--password`
flag — a flag would show up in `docker compose exec`'s process listing, an
environment variable doesn't.

Refuses to run if the username already exists — use the Users page (or
another superadmin account) to manage it from there on.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import select

from app.auth.security import USERNAME_PATTERN, hash_password
from app.db.models.user import AuthProvider, User
from app.db.session import AsyncSessionLocal

_MIN_PASSWORD_LENGTH = 12


async def _create_admin(username: str, password: str) -> None:
    username = username.strip().lower()
    if not USERNAME_PATTERN.match(username):
        print(
            f'error: "{username}" isn\'t a valid username '
            "(3-64 chars: lowercase letters, digits, '.', '_', '-').",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if len(password) < _MIN_PASSWORD_LENGTH:
        print(
            f"error: password must be at least {_MIN_PASSWORD_LENGTH} characters.", file=sys.stderr
        )
        raise SystemExit(1)

    async with AsyncSessionLocal() as db:
        existing_result = await db.execute(select(User).where(User.username == username))
        if existing_result.scalar_one_or_none() is not None:
            print(f'error: a user named "{username}" already exists.', file=sys.stderr)
            raise SystemExit(1)

        user = User(
            username=username,
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password(password),
            must_change_password=True,
            is_superadmin=True,
            company_id=None,
            access_level=None,
        )
        db.add(user)
        await db.commit()

    print(
        f'Created "{username}" as a superadmin. '
        "They'll be asked to change this password on first login."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True, help="Login name for the new superadmin.")
    args = parser.parse_args()

    password = os.environ.get("HONEYHIVE_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Confirm password: ") != password:
            print("error: passwords didn't match.", file=sys.stderr)
            raise SystemExit(1)

    asyncio.run(_create_admin(args.username, password))


if __name__ == "__main__":
    main()
