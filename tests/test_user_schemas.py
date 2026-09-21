"""`app.schemas.user.looks_like_email` — the loose email-shape check
shared by the account email field, a notification rule's target email
override, and the admin Users form."""

from __future__ import annotations

from app.schemas.user import looks_like_email


def test_accepts_a_plausible_address():
    assert looks_like_email("user@example.com") is True


def test_rejects_missing_at_sign():
    assert looks_like_email("not-an-email") is False


def test_rejects_missing_domain_dot():
    assert looks_like_email("user@example") is False


def test_rejects_an_address_longer_than_rfc_5321s_own_cap():
    """Regression test for a CodeQL polynomial-ReDoS finding: the regex's
    two `[^\\s@]+` groups can each also match "." characters, so a long
    "@"-less string makes the engine try many ways to split it before
    failing — polynomial in the input length. A real address is always
    far under RFC 5321's 254-character cap, so rejecting anything longer
    up front (cheap, no backtracking) keeps that bounded regardless of
    what a caller passes in. This must return promptly, not hang."""
    pathological = "a" * 100_000
    assert looks_like_email(pathological) is False
