"""Resolve the credential material to authenticate a honeypot's SSH connection."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.db.models.honeypot import AuthMethod, Honeypot
from app.ssh.identity import get_or_create_identity


async def resolve_honeypot_credential(honeypot: Honeypot, db: AsyncSession) -> str | None:
    """Return the secret to pass to `app.ssh.client.open_connection`.

    For `AuthMethod.SSH_KEY` (the default), that's the app's own shared
    private key (decrypted on the fly, never written to disk). For
    `AuthMethod.PASSWORD`, it's whatever password is stored on the honeypot
    itself, if any.
    """
    if honeypot.auth_method == AuthMethod.PASSWORD:
        return decrypt_secret(honeypot.secret_encrypted) if honeypot.secret_encrypted else None

    identity = await get_or_create_identity(db)
    return decrypt_secret(identity.private_key_encrypted)
