"""Tests for borg.legacy.crypto.key (Pbkdf2FileMixin)."""

import pytest

from ...crypto.key import UnsupportedKeyFormatError
from ...helpers import msgpack
from ...legacy.crypto.key import KeyfileKey as LegacyKeyfileKey


# ── Pbkdf2FileMixin ───────────────────────────────────────────────────────────


def test_pbkdf2_encrypt_decrypt_roundtrip():
    # encrypt_key_file dispatches to encrypt_key_file_pbkdf2; decrypt_key_file
    # dispatches back — the round-trip must recover the original plaintext
    key_obj = LegacyKeyfileKey(None)
    plaintext = b"secret key material"
    blob = key_obj.encrypt_key_file(plaintext, "correct passphrase", "sha256")
    assert key_obj.decrypt_key_file(blob, "correct passphrase") == plaintext


def test_pbkdf2_wrong_passphrase_returns_none():
    # a wrong passphrase derives a different key, so the HMAC check fails;
    # decrypt_key_file signals this by returning None, not by raising
    key_obj = LegacyKeyfileKey(None)
    blob = key_obj.encrypt_key_file(b"secret key material", "correct passphrase", "sha256")
    assert key_obj.decrypt_key_file(blob, "wrong passphrase") is None


def test_pbkdf2_unsupported_version_raises():
    # only version 1 is defined in the borg 1.x format; anything else must raise
    blob = msgpack.packb({"version": 99})
    with pytest.raises(UnsupportedKeyFormatError):
        LegacyKeyfileKey(None).decrypt_key_file(blob, "pass")
