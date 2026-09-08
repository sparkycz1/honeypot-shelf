"""Per-honeypot ingest tokens — an alternative to the shared `INGEST_TOKEN`
for `POST /api/ingest/{honeypot_id}/events` (see `app.web.routes.ingest`).

Same scheme as `app.auth.api_tokens`/`app.auth.sessions`: a random value
prefixed for recognizability, only its SHA-256 hash ever stored
(`Honeypot.ingest_token_hash`). Unlike API tokens there's no separate table
— one honeypot has at most one ingest token, so the hash lives directly on
`Honeypot` and there's nothing to list/name, just generate/revoke.
"""

from __future__ import annotations

import hashlib
import secrets

from app.db.models.honeypot import Honeypot

_TOKEN_PREFIX = "hhit_"  # noqa: S105 - a public format prefix, not a secret value


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_ingest_token(honeypot: Honeypot) -> str:
    """Generates a fresh token, stores its hash on `honeypot` (overwriting
    any previous one — there's only ever one live token per honeypot), and
    returns the raw value. The caller must show it to the operator now —
    it can never be retrieved again, only regenerated."""
    raw_token = _TOKEN_PREFIX + secrets.token_urlsafe(32)
    honeypot.ingest_token_hash = _hash_token(raw_token)
    return raw_token


def revoke_ingest_token(honeypot: Honeypot) -> None:
    honeypot.ingest_token_hash = None
