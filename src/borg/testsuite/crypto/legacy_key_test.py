"""Tests for borg.legacy.crypto.key (Pbkdf2FileMixin)."""

import pytest

from ...crypto.key import UnsupportedKeyFormatError
from ...helpers import msgpack, hex_to_bin
from ...legacy.crypto.key import AESCTRKey as LegacyAESCTRKey
from ...legacy.crypto.key import AuthenticatedKey as LegacyAuthenticatedKey
from ...legacy.crypto.key import Blake2AuthenticatedKey as LegacyBlake2AuthenticatedKey


# ── Pbkdf2FileMixin ───────────────────────────────────────────────────────────


def test_pbkdf2_encrypt_decrypt_roundtrip():
    # encrypt_key_file dispatches to encrypt_key_file_pbkdf2; decrypt_key_file
    # dispatches back — the round-trip must recover the original plaintext
    key_obj = LegacyAESCTRKey(None)
    plaintext = b"secret key material"
    blob = key_obj.encrypt_key_file(plaintext, "correct passphrase", "sha256")
    assert key_obj.decrypt_key_file(blob, "correct passphrase") == plaintext


def test_pbkdf2_wrong_passphrase_returns_none():
    # a wrong passphrase derives a different key, so the HMAC check fails;
    # decrypt_key_file signals this by returning None, not by raising
    key_obj = LegacyAESCTRKey(None)
    blob = key_obj.encrypt_key_file(b"secret key material", "correct passphrase", "sha256")
    assert key_obj.decrypt_key_file(blob, "wrong passphrase") is None


def test_pbkdf2_unsupported_version_raises():
    # only version 1 is defined in the borg 1.x format; anything else must raise
    blob = msgpack.packb({"version": 99})
    with pytest.raises(UnsupportedKeyFormatError):
        LegacyAESCTRKey(None).decrypt_key_file(blob, "pass")


# ── borg 1.x authenticated modes ──────────────────────────────────────────────

# "borg key export" output of borg 1.4.5 repositories made with "borg init -e authenticated" and
# "borg init -e authenticated-blake2": the key is protected with the passphrase (pbkdf2, sha256).
BORG1_PASSPHRASE = "borg1 authenticated test"
BORG1_AUTHENTICATED_KEY = """\
BORG_KEY 50deff815475cf32e4379ff515675b73537b2cb49575d947dc90bfab32451b05
hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAN5/K1apbgs7NqPqcf2ZGS2aHSKTovoA9nn7Zv
T9/utA9+8Bv33Gb8fkcoj7xt/0ulcwhnZFzm+r/KLTuems44vHfg5oeq/y+ultd9lEDd3n
fhTVOKwEcW5TStXg4rn40aFlrU+EPMa7kq8zSVEsLDv/eN6SYTqSU+MopYFXwBNfA8YAwC
z91muHUxzIVze7h63gI4aRA3lVqQuD4KUO6/LMN8jpsq+L6EN7lk0HVxw1Qe9JXsR1Y2Rb
ISuTcX+Oog5wLN978mx4rb4k1vkYIGCWCANV933CHGcQsyVe87ikaGFzaNoAIAXdXdnSbs
ZuSCD6KS0eqlWVo05WfmYJLIinaHHgzfE/qml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgfpGO
IAXz14z4Z0HCXsh8EQru7cLuYCfrTicWQyzif7CndmVyc2lvbgE=
"""
BORG1_AUTHENTICATED_BLAKE2_KEY = """\
BORG_KEY 224728eac45fbadb93560aab651f2650de228e3c4129e3951b69f87dd8bf69dc
hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6xkbEs3D7ShF0pv7Wm1IkoYNb5tYEX26yxey
o+96hGCgOfhFiVZHjxqZOIEDBrKlZLeVCNZip1MuB6h6kdpDN85PfQap8oaoxORu7kFl87
GnxNee5l2z4YeG3YD46xErcUmcbrBi9OA1uAFXbdwK9TlXYKXZCCmT0aQ3/zTo9qFNAu5n
6FHpW4vaVBF0C53sVXjTs8ApYhdb2G3gZKm+RQ+VApygrXaacQaeS61Xy8FjkhKcgHo8Wa
LTKdsce1vR79QzXCo9WdoIJ5F5hNov2AdmL35T0pN+zqOHzidK1sKIV00Z0SDjYGyek17b
RG42YgNUivsUfGxp+2JUnBl28w9xb7U1kMmdTw5CJBYWNQkyUumcyvtQA73laMYKonHxiC
E7Ww/u0Yq5PrCqXRCSoh1c6GyPoPzXZ9fgOjXOlOXt9pEh7lBVG9tQOLvWmfjt5+R/Zsz1
nRsFdmTs09o2LuwNbyx3/t7jg5TnTXH4rMfmegytaLOOyBTLs6IawTf0Tha5epV/m5f+Wj
Lxnd1Y/yeMh82DYsI+kCq1FPG6ekaGFzaNoAIO/0ioA/h3VazNMd9wDFmgOXon31VRxrNS
rM4tL66FYeqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgFqPvW/r2z7qxksL1lCFcIaTo/nrt
fCQasDsJ0haVHcundmVyc2lvbgE=
"""


@pytest.mark.parametrize(
    "key_cls, exported_key",
    [(LegacyAuthenticatedKey, BORG1_AUTHENTICATED_KEY), (LegacyBlake2AuthenticatedKey, BORG1_AUTHENTICATED_BLAKE2_KEY)],
    ids=["authenticated", "authenticated-blake2"],
)
def test_borg1_authenticated_key_load(monkeypatch, key_cls, exported_key):
    # the key must be decrypted with the real pbkdf2 iterations it was made with.
    monkeypatch.delenv("BORG_TESTONLY_WEAKEN_KDF", raising=False)
    header, *lines = exported_key.splitlines()
    key_obj = key_cls(None)
    assert not key_obj._load("".join(lines), "wrong passphrase")
    assert key_obj._load("".join(lines), BORG1_PASSPHRASE)
    assert key_obj.repository_id == hex_to_bin(header.split()[1])
