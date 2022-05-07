# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from binascii import hexlify

from ..crypto.low_level import AES256_CTR_HMAC_SHA256, UNENCRYPTED, IntegrityError
from ..crypto.low_level import bytes_to_long, bytes_to_int, long_to_bytes
from ..crypto.low_level import hkdf_hmac_sha512

from . import BaseTestCase


class CryptoTestCase(BaseTestCase):

    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes_to_long(self):
        self.assert_equal(bytes_to_long(b'\0\0\0\0\0\0\0\1'), 1)
        self.assert_equal(long_to_bytes(1), b'\0\0\0\0\0\0\0\1')

    def test_UNENCRYPTED(self):
        iv = b''  # any IV is ok, it just must be set and not None
        data = b'data'
        header = b'header'
        cs = UNENCRYPTED(None, None, iv, header_len=6)
        envelope = cs.encrypt(data, header=header)
        self.assert_equal(envelope, header + data)
        got_data = cs.decrypt(envelope)
        self.assert_equal(got_data, data)

    def test_AES256_CTR_HMAC_SHA256(self):
        # this tests the layout as in attic / borg < 1.2 (1 type byte, no aad)
        mac_key = b'Y' * 32
        enc_key = b'X' * 32
        iv = 0
        data = b'foo' * 10
        header = b'\x42'
        # encrypt-then-mac
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, iv, header_len=1, aad_offset=1)
        hdr_mac_iv_cdata = cs.encrypt(data, header=header)
        hdr = hdr_mac_iv_cdata[0:1]
        mac = hdr_mac_iv_cdata[1:33]
        iv = hdr_mac_iv_cdata[33:41]
        cdata = hdr_mac_iv_cdata[41:]
        self.assert_equal(hexlify(hdr), b'42')
        self.assert_equal(hexlify(mac), b'af90b488b0cc4a8f768fe2d6814fa65aec66b148135e54f7d4d29a27f22f57a8')
        self.assert_equal(hexlify(iv), b'0000000000000000')
        self.assert_equal(hexlify(cdata), b'c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466')
        self.assert_equal(cs.next_iv(), 2)
        # auth-then-decrypt
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        pdata = cs.decrypt(hdr_mac_iv_cdata)
        self.assert_equal(data, pdata)
        self.assert_equal(cs.next_iv(), 2)
        # auth-failure due to corruption (corrupted data)
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:41] + b'\0' + hdr_mac_iv_cdata[42:]
        self.assert_raises(IntegrityError,
                           lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AES256_CTR_HMAC_SHA256_aad(self):
        mac_key = b'Y' * 32
        enc_key = b'X' * 32
        iv = 0
        data = b'foo' * 10
        header = b'\x12\x34\x56'
        # encrypt-then-mac
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, iv, header_len=3, aad_offset=1)
        hdr_mac_iv_cdata = cs.encrypt(data, header=header)
        hdr = hdr_mac_iv_cdata[0:3]
        mac = hdr_mac_iv_cdata[3:35]
        iv = hdr_mac_iv_cdata[35:43]
        cdata = hdr_mac_iv_cdata[43:]
        self.assert_equal(hexlify(hdr), b'123456')
        self.assert_equal(hexlify(mac), b'7659a915d9927072ef130258052351a17ef882692893c3850dd798c03d2dd138')
        self.assert_equal(hexlify(iv), b'0000000000000000')
        self.assert_equal(hexlify(cdata), b'c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466')
        self.assert_equal(cs.next_iv(), 2)
        # auth-then-decrypt
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        pdata = cs.decrypt(hdr_mac_iv_cdata)
        self.assert_equal(data, pdata)
        self.assert_equal(cs.next_iv(), 2)
        # auth-failure due to corruption (corrupted aad)
        cs = AES256_CTR_HMAC_SHA256(mac_key, enc_key, header_len=len(header), aad_offset=1)
        hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:1] + b'\0' + hdr_mac_iv_cdata[2:]
        self.assert_raises(IntegrityError,
                           lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    # These test vectors come from https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
    # who claims to have verified these against independent Python and C++ implementations.

    def test_hkdf_hmac_sha512(self):
        ikm = b'\x0b' * 22
        salt = bytes.fromhex('000102030405060708090a0b0c')
        info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
        l = 42

        okm = hkdf_hmac_sha512(ikm, salt, info, l)
        assert okm == bytes.fromhex('832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb')

    def test_hkdf_hmac_sha512_2(self):
        ikm = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627'
                            '28292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f')
        salt = bytes.fromhex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868'
                             '788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
        info = bytes.fromhex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7'
                             'd8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
        l = 82

        okm = hkdf_hmac_sha512(ikm, salt, info, l)
        assert okm == bytes.fromhex('ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c838844'
                                    '1137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93')

    def test_hkdf_hmac_sha512_3(self):
        ikm = bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
        salt = None
        info = b''
        l = 42

        okm = hkdf_hmac_sha512(ikm, salt, info, l)
        assert okm == bytes.fromhex('f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac')

    def test_hkdf_hmac_sha512_4(self):
        ikm = bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b')
        salt = bytes.fromhex('000102030405060708090a0b0c')
        info = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
        l = 42

        okm = hkdf_hmac_sha512(ikm, salt, info, l)
        assert okm == bytes.fromhex('7413e8997e020610fbf6823f2ce14bff01875db1ca55f68cfcf3954dc8aff53559bd5e3028b080f7c068')

    def test_hkdf_hmac_sha512_5(self):
        ikm = bytes.fromhex('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c')
        salt = None
        info = b''
        l = 42

        okm = hkdf_hmac_sha512(ikm, salt, info, l)
        assert okm == bytes.fromhex('1407d46013d98bc6decefcfee55f0f90b0c7f63d68eb1a80eaf07e953cfc0a3a5240a155d6e4daa965bb')
