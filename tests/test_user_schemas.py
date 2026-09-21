"""`app.schemas.user.looks_like_email` — the loose email-shape check
shared by the account email field, a notification rule's target email
override, and the admin Users form."""

from __future__ import annotations

import time

from app.schemas.user import looks_like_email


def test_accepts_a_plausible_address():
    assert looks_like_email("user@example.com") is True


def test_accepts_a_multi_label_domain():
    assert looks_like_email("user@mail.sub.example.com") is True


def test_rejects_missing_at_sign():
    assert looks_like_email("not-an-email") is False


def test_rejects_missing_domain_dot():
    assert looks_like_email("user@example") is False


def test_does_not_blow_up_on_the_pathological_input_codeql_flagged():
    """Regression test for a CodeQL polynomial-ReDoS finding: the earlier
    pattern's domain-side group (`[^\\s@]+` before the literal ".") could
    also match "." characters itself, so a string built from many "!."
    repetitions gave the engine many different ways to divide it between
    the two groups before failing — polynomial in the input length,
    exactly the attack string CodeQL's own finding named. The domain side
    is now a dot-separated run of labels that each exclude "." (so every
    character belongs to exactly one possible group), which removes the
    ambiguity entirely — this must return promptly, not hang, with no
    length cap needed to make that true."""
    pathological = "!@!." + "!." * 50_000
    started = time.monotonic()
    assert looks_like_email(pathological) is False
    assert time.monotonic() - started < 1.0
