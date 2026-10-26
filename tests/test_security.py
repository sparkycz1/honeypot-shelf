"""Encryption at rest — `app.core.security`. New values are AES-256-GCM;
`decrypt_secret` must still transparently read a value stored in the
legacy Fernet (AES-128) format from before this app moved to AES-256. See
that module's docstring and wiki/Architecture.md's "FIPS alignment"
section.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet

from app.core.config import get_settings
from app.core.security import (
    DecryptionError,
    decrypt_secret,
    encrypt_secret,
    is_legacy_ciphertext,
)


def test_round_trips_a_secret():
    ciphertext = encrypt_secret("correct horse battery staple")
    assert decrypt_secret(ciphertext) == "correct horse battery staple"


def test_new_ciphertext_is_not_a_legacy_fernet_token():
    ciphertext = encrypt_secret("whatever")
    assert is_legacy_ciphertext(ciphertext) is False
    # Not base64-text-shaped like a Fernet token — starts with the raw
    # 0x02 version byte.
    assert ciphertext[0] == 0x02


def test_two_encryptions_of_the_same_plaintext_differ():
    # Each call uses a fresh random nonce — ciphertext must never repeat
    # for the same plaintext (a static/reused nonce would be an AES-GCM
    # confidentiality break, not just a style nit).
    first = encrypt_secret("same plaintext")
    second = encrypt_secret("same plaintext")
    assert first != second


def test_reads_a_legacy_fernet_ciphertext():
    key = get_settings().encryption_key.get_secret_value()
    legacy_ciphertext = Fernet(key.encode("utf-8")).encrypt(b"old-style secret")

    assert is_legacy_ciphertext(legacy_ciphertext) is True
    assert decrypt_secret(legacy_ciphertext) == "old-style secret"


def test_tampered_ciphertext_raises_decryption_error():
    ciphertext = bytearray(encrypt_secret("tamper with me"))
    ciphertext[-1] ^= 0xFF  # flip a bit in the GCM tag

    with pytest.raises(DecryptionError):
        decrypt_secret(bytes(ciphertext))


def test_tampered_legacy_fernet_ciphertext_raises_decryption_error():
    key = get_settings().encryption_key.get_secret_value()
    token = base64.urlsafe_b64decode(Fernet(key.encode("utf-8")).encrypt(b"old-style secret"))
    tampered = bytearray(token)
    tampered[-1] ^= 0xFF  # flip a bit in the HMAC
    # Tamper with the decoded token, not its base64 text: flipping the
    # trailing "=" padding turns it into a non-base64 byte the decoder just
    # skips, and since Python 3.15 the missing padding isn't an error either,
    # so the original token would decode intact.
    legacy_ciphertext = base64.urlsafe_b64encode(bytes(tampered))

    with pytest.raises(DecryptionError):
        decrypt_secret(bytes(legacy_ciphertext))
