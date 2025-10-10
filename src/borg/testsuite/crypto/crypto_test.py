# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from unittest.mock import MagicMock
import unittest

from ...crypto.low_level import AES256_CTR_HMAC_SHA256, AES256_OCB, CHACHA20_POLY1305, UNENCRYPTED, IntegrityError
from ...crypto.low_level import bytes_to_long, bytes_to_int, long_to_bytes
from ...crypto.low_level import AES, hmac_sha256
from hashlib import sha256
from ...crypto.key import CHPOKeyfileKey, AESOCBRepoKey, FlexiKey, KeyBase, PlaintextKey
from ...helpers import msgpack, bin_to_hex

from .. import BaseTestCase


class CryptoTestCase(BaseTestCase):
    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b"\0\0\0\1"), 1)

    def test_bytes_to_long(self):
        self.assert_equal(bytes_to_long(b"\0\0\0\0\0\0\0\1"), 1)
        self.assert_equal(long_to_bytes(1), b"\0\0\0\0\0\0\0\1")

    def test_UNENCRYPTED(self):
        iv = b""  # any IV is ok, it just must be set and not None
        data = b"data"
        header = b"header"
        cs = UNENCRYPTED(None, None, iv, header_len=6)
        envelope = cs.encrypt(data, header=header)
        self.assert_equal(envelope, header + data)
        got_data = cs.decrypt(envelope)
        self.assert_equal(got_data, data)

    def test_AES256_CTR_HMAC_SHA256(self):
        # this tests the layout as in borg < 1.2 (1 type byte, no aad)
        mac_key = b"Y" * 32
        enc_key = b"X" * 32
        iv = 0
        data = b"foo" * 10
        header = b"\x42"
        # encrypt-then-mac
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, iv, header_len=1, aad_offset=1)
        hdr_mac_iv_cdata = cs.encrypt(data, header=header)
        hdr = hdr_mac_iv_cdata[0:1]
        mac = hdr_mac_iv_cdata[1:33]
        iv = hdr_mac_iv_cdata[33:41]
        cdata = hdr_mac_iv_cdata[41:]
        self.assert_equal(bin_to_hex(hdr), "42")
        self.assert_equal(bin_to_hex(mac), "af90b488b0cc4a8f768fe2d6814fa65aec66b148135e54f7d4d29a27f22f57a8")
        self.assert_equal(bin_to_hex(iv), "0000000000000000")
        self.assert_equal(bin_to_hex(cdata), "c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466")
        self.assert_equal(cs.next_iv(), 2)
        # auth-then-decrypt
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        pdata = cs.decrypt(hdr_mac_iv_cdata)
        self.assert_equal(data, pdata)
        self.assert_equal(cs.next_iv(), 2)
        # auth-failure due to corruption (corrupted data)
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:41] + b"\0" + hdr_mac_iv_cdata[42:]
        self.assert_raises(IntegrityError, lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AES256_CTR_HMAC_SHA256_aad(self):
        mac_key = b"Y" * 32
        enc_key = b"X" * 32
        iv = 0
        data = b"foo" * 10
        header = b"\x12\x34\x56"
        # encrypt-then-mac
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, iv, header_len=3, aad_offset=1)
        hdr_mac_iv_cdata = cs.encrypt(data, header=header)
        hdr = hdr_mac_iv_cdata[0:3]
        mac = hdr_mac_iv_cdata[3:35]
        iv = hdr_mac_iv_cdata[35:43]
        cdata = hdr_mac_iv_cdata[43:]
        self.assert_equal(bin_to_hex(hdr), "123456")
        self.assert_equal(bin_to_hex(mac), "7659a915d9927072ef130258052351a17ef882692893c3850dd798c03d2dd138")
        self.assert_equal(bin_to_hex(iv), "0000000000000000")
        self.assert_equal(bin_to_hex(cdata), "c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466")
        self.assert_equal(cs.next_iv(), 2)
        # auth-then-decrypt
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        pdata = cs.decrypt(hdr_mac_iv_cdata)
        self.assert_equal(data, pdata)
        self.assert_equal(cs.next_iv(), 2)
        # auth-failure due to corruption (corrupted aad)
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:1] + b"\0" + hdr_mac_iv_cdata[2:]
        self.assert_raises(IntegrityError, lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AE(self):
        # used in legacy-like layout (1 type byte, no aad)
        key = b"X" * 32
        iv_int = 0
        data = b"foo" * 10
        header = b"\x23" + iv_int.to_bytes(12, "big")
        tests = [
            # (ciphersuite class, exp_mac, exp_cdata)
            (
                AES256_OCB,
                "b6909c23c9aaebd9abbe1ff42097652d",
                "877ce46d2f62dee54699cebc3ba41d9ab613f7c486778c1b3636664b1493",
            ),
            (
                CHACHA20_POLY1305,
                "fd08594796e0706cde1e8b461e3e0555",
                "a093e4b0387526f085d3c40cca84a35230a5c0dd766453b77ba38bcff775",
            ),
        ]
        for cs_cls, exp_mac, exp_cdata in tests:
            # print(repr(cs_cls))
            # encrypt/mac
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata = cs.encrypt(data, header=header)
            hdr = hdr_mac_iv_cdata[0:1]
            iv = hdr_mac_iv_cdata[1:13]
            mac = hdr_mac_iv_cdata[13:29]
            cdata = hdr_mac_iv_cdata[29:]
            self.assert_equal(bin_to_hex(hdr), "23")
            self.assert_equal(bin_to_hex(mac), exp_mac)
            self.assert_equal(bin_to_hex(iv), "000000000000000000000000")
            self.assert_equal(bin_to_hex(cdata), exp_cdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth/decrypt
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            pdata = cs.decrypt(hdr_mac_iv_cdata)
            self.assert_equal(data, pdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth-failure due to corruption (corrupted data)
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:29] + b"\0" + hdr_mac_iv_cdata[30:]
            self.assert_raises(IntegrityError, lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AEAD(self):
        # test with aad
        key = b"X" * 32
        iv_int = 0
        data = b"foo" * 10
        header = b"\x12\x34\x56" + iv_int.to_bytes(12, "big")
        tests = [
            # (ciphersuite class, exp_mac, exp_cdata)
            (
                AES256_OCB,
                "f2748c412af1c7ead81863a18c2c1893",
                "877ce46d2f62dee54699cebc3ba41d9ab613f7c486778c1b3636664b1493",
            ),
            (
                CHACHA20_POLY1305,
                "b7e7c9a79f2404e14f9aad156bf091dd",
                "a093e4b0387526f085d3c40cca84a35230a5c0dd766453b77ba38bcff775",
            ),
        ]
        for cs_cls, exp_mac, exp_cdata in tests:
            # print(repr(cs_cls))
            # encrypt/mac
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata = cs.encrypt(data, header=header)
            hdr = hdr_mac_iv_cdata[0:3]
            iv = hdr_mac_iv_cdata[3:15]
            mac = hdr_mac_iv_cdata[15:31]
            cdata = hdr_mac_iv_cdata[31:]
            self.assert_equal(bin_to_hex(hdr), "123456")
            self.assert_equal(bin_to_hex(mac), exp_mac)
            self.assert_equal(bin_to_hex(iv), "000000000000000000000000")
            self.assert_equal(bin_to_hex(cdata), exp_cdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth/decrypt
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            pdata = cs.decrypt(hdr_mac_iv_cdata)
            self.assert_equal(data, pdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth-failure due to corruption (corrupted aad)
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:1] + b"\0" + hdr_mac_iv_cdata[2:]
            self.assert_raises(IntegrityError, lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AEAD_with_more_AAD(self):
        # test giving extra aad to the .encrypt() and .decrypt() calls
        key = b"X" * 32
        iv_int = 0
        data = b"foo" * 10
        header = b"\x12\x34"
        tests = [AES256_OCB, CHACHA20_POLY1305]
        for cs_cls in tests:
            # encrypt/mac
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=0)
            hdr_mac_iv_cdata = cs.encrypt(data, header=header, aad=b"correct_chunkid")
            # successful auth/decrypt (correct aad)
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=0)
            pdata = cs.decrypt(hdr_mac_iv_cdata, aad=b"correct_chunkid")
            self.assert_equal(data, pdata)
            # unsuccessful auth (incorrect aad)
            cs = cs_cls(key, iv_int, header_len=len(header), aad_offset=0)
            self.assert_raises(IntegrityError, lambda: cs.decrypt(hdr_mac_iv_cdata, aad=b"incorrect_chunkid"))


def test_decrypt_key_file_argon2_chacha20_poly1305():
    plain = b"hello"
    # echo -n "hello, pass phrase" | argon2 saltsaltsaltsalt -id -t 1 -k 8 -p 1 -l 32 -r
    key = bytes.fromhex("a1b0cba145c154fbd8960996c5ce3428e9920cfe53c84ef08b4102a70832bcec")
    ae_cipher = CHACHA20_POLY1305(key=key, iv=0, header_len=0, aad_offset=0)

    envelope = ae_cipher.encrypt(plain)

    encrypted = msgpack.packb(
        {
            "version": 1,
            "salt": b"salt" * 4,
            "argon2_time_cost": 1,
            "argon2_memory_cost": 8,
            "argon2_parallelism": 1,
            "argon2_type": b"id",
            "algorithm": "argon2 chacha20-poly1305",
            "data": envelope,
        }
    )
    key = CHPOKeyfileKey(None)

    decrypted = key.decrypt_key_file(encrypted, "hello, pass phrase")

    assert decrypted == plain


def test_decrypt_key_file_pbkdf2_sha256_aes256_ctr_hmac_sha256():
    plain = b"hello"
    salt = b"salt" * 4
    passphrase = "hello, pass phrase"
    key = FlexiKey.pbkdf2(passphrase, salt, 1, 32)
    hash = hmac_sha256(key, plain)
    data = AES(key, b"\0" * 16).encrypt(plain)
    encrypted = msgpack.packb(
        {"version": 1, "algorithm": "sha256", "iterations": 1, "salt": salt, "data": data, "hash": hash}
    )
    key = CHPOKeyfileKey(None)

    decrypted = key.decrypt_key_file(encrypted, passphrase)

    assert decrypted == plain


@unittest.mock.patch("getpass.getpass")
def test_repo_key_detect_does_not_raise_integrity_error(getpass, monkeypatch):
    """https://github.com/borgbackup/borg/pull/6469#discussion_r832670411

    This is a regression test for a bug I introduced and fixed:

    Traceback (most recent call last):
      File "/home/user/borg-master/src/borg/testsuite/crypto.py", line 384,
                                                                  in test_repo_key_detect_does_not_raise_integrity_error
        RepoKey.detect(repository, manifest_data=None)
      File "/home/user/borg-master/src/borg/crypto/key.py", line 402, in detect
        if not key.load(target, passphrase):
      File "/home/user/borg-master/src/borg/crypto/key.py", line 654, in load
        success = self._load(key_data, passphrase)
      File "/home/user/borg-master/src/borg/crypto/key.py", line 418, in _load
        data = self.decrypt_key_file(cdata, passphrase)
      File "/home/user/borg-master/src/borg/crypto/key.py", line 444, in decrypt_key_file
        return self.decrypt_key_file_argon2(encrypted_key, passphrase)
      File "/home/user/borg-master/src/borg/crypto/key.py", line 470, in decrypt_key_file_argon2
        return ae_cipher.decrypt(encrypted_key.data)
      File "src/borg/crypto/low_level.pyx", line 302, in borg.crypto.low_level.AES256_CTR_BASE.decrypt
        self.mac_verify(<const unsigned char *> idata.buf+aoffset, alen,
      File "src/borg/crypto/low_level.pyx", line 382, in borg.crypto.low_level.AES256_CTR_HMAC_SHA256.mac_verify
        raise IntegrityError('MAC Authentication failed')
    borg.crypto.low_level.IntegrityError: MAC Authentication failed

    1. FlexiKey.decrypt_key_file() is supposed to signal the decryption failure by returning None
    2. FlexiKey.detect() relies on that interface - it tries an empty passphrase before prompting the user
    3. my initial implementation of decrypt_key_file_argon2() was simply passing through the IntegrityError()
       from AES256_CTR_BASE.decrypt()
    """
    repository = MagicMock(id=b"repository_id")
    getpass.return_value = "hello, pass phrase"
    monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "no")
    AESOCBRepoKey.create(repository, args=MagicMock(key_algorithm="argon2"))
    repository.load_key.return_value = repository.save_key.call_args.args[0]

    AESOCBRepoKey.detect(repository, manifest_data=None)


class TestDeriveKey(BaseTestCase):
    # Create a simple KeyBase subclass with a non-empty crypt_key
    class CustomKey(KeyBase):
        def __init__(self, crypt_key, id_key):
            self.crypt_key = crypt_key
            self.id_key = id_key

    def test_derive_key_with_plaintext_key(self):
        """Test derive_key with PlaintextKey (empty crypt_key)"""
        key = PlaintextKey(None)
        salt, domain, size = b"salt", b"domain", 16

        # PlaintextKey has an empty crypt_key, so the derived key should be based on salt and domain only
        derived_key = key.derive_key(salt=salt, domain=domain, size=size)
        expected = sha256(b"" + salt + domain).digest()[:size]
        self.assert_equal(derived_key, expected)

    def test_derive_key_with_custom_key(self):
        """Test derive_key with a custom KeyBase subclass (non-empty crypt_key)"""
        crypt_key, id_key = b"test_crypt_key", b"test_id_key"
        key = self.CustomKey(crypt_key, id_key)
        salt, domain, size = b"salt", b"domain", 32

        # derived key size and value as expected
        expected = sha256(crypt_key + salt + domain).digest()[:size]
        derived_key = key.derive_key(salt=salt, domain=domain, size=size)
        self.assert_equal(derived_key, expected)

        # domain separation
        derived_key = key.derive_key(salt=salt, domain=b"other_domain", size=size)
        assert derived_key != expected
        assert len(derived_key) == size

        # salt separation
        derived_key = key.derive_key(salt=b"other salt", domain=domain, size=size)
        assert derived_key != expected
        assert len(derived_key) == size

    def test_derive_key_from_different_keys(self):
        """Test derive_key with different key material"""
        crypt_key, id_key = b"test_crypt_key", b"test_id_key"
        key = self.CustomKey(crypt_key, id_key)
        salt, domain, size = b"salt", b"domain", 32

        # derived key size and value as expected (using the ID key)
        expected = sha256(id_key + salt + domain).digest()[:size]
        derived_key = key.derive_key(salt=salt, domain=domain, size=size, from_id_key=True)
        self.assert_equal(derived_key, expected)

        # generating different keys from crypt_key and id_key
        derived_key_from_id = key.derive_key(salt=salt, domain=domain, size=size, from_id_key=True)
        derived_key_from_crypt = key.derive_key(salt=salt, domain=domain, size=size, from_id_key=False)
        assert derived_key_from_id != derived_key_from_crypt
