from binascii import hexlify, unhexlify

from ..crypto.low_level import AES256_CTR_HMAC_SHA256, AES256_OCB, CHACHA20_POLY1305, UNENCRYPTED, \
                               IntegrityError, blake2b_256, hmac_sha256, openssl10
from ..crypto.low_level import bytes_to_long, bytes_to_int, long_to_bytes
from ..crypto.low_level import hkdf_hmac_sha512

from . import BaseTestCase

# Note: these tests are part of the self test, do not use or import py.test functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT


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

    def test_AE(self):
        # used in legacy-like layout (1 type byte, no aad)
        mac_key = None
        enc_key = b'X' * 32
        iv = 0
        data = b'foo' * 10
        header = b'\x23'
        tests = [
            # (ciphersuite class, exp_mac, exp_cdata)
        ]
        if not openssl10:
            tests += [
                (AES256_OCB,
                 b'b6909c23c9aaebd9abbe1ff42097652d',
                 b'877ce46d2f62dee54699cebc3ba41d9ab613f7c486778c1b3636664b1493', ),
                (CHACHA20_POLY1305,
                 b'fd08594796e0706cde1e8b461e3e0555',
                 b'a093e4b0387526f085d3c40cca84a35230a5c0dd766453b77ba38bcff775', )
            ]
        for cs_cls, exp_mac, exp_cdata in tests:
            # print(repr(cs_cls))
            # encrypt/mac
            cs = cs_cls(mac_key, enc_key, iv, header_len=1, aad_offset=1)
            hdr_mac_iv_cdata = cs.encrypt(data, header=header)
            hdr = hdr_mac_iv_cdata[0:1]
            mac = hdr_mac_iv_cdata[1:17]
            iv = hdr_mac_iv_cdata[17:29]
            cdata = hdr_mac_iv_cdata[29:]
            self.assert_equal(hexlify(hdr), b'23')
            self.assert_equal(hexlify(mac), exp_mac)
            self.assert_equal(hexlify(iv), b'000000000000000000000000')
            self.assert_equal(hexlify(cdata), exp_cdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth/decrypt
            cs = cs_cls(mac_key, enc_key, header_len=len(header), aad_offset=1)
            pdata = cs.decrypt(hdr_mac_iv_cdata)
            self.assert_equal(data, pdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth-failure due to corruption (corrupted data)
            cs = cs_cls(mac_key, enc_key, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:29] + b'\0' + hdr_mac_iv_cdata[30:]
            self.assert_raises(IntegrityError,
                               lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_AEAD(self):
        # test with aad
        mac_key = None
        enc_key = b'X' * 32
        iv = 0
        data = b'foo' * 10
        header = b'\x12\x34\x56'
        tests = [
            # (ciphersuite class, exp_mac, exp_cdata)
        ]
        if not openssl10:
            tests += [
                (AES256_OCB,
                 b'f2748c412af1c7ead81863a18c2c1893',
                 b'877ce46d2f62dee54699cebc3ba41d9ab613f7c486778c1b3636664b1493', ),
                (CHACHA20_POLY1305,
                 b'b7e7c9a79f2404e14f9aad156bf091dd',
                 b'a093e4b0387526f085d3c40cca84a35230a5c0dd766453b77ba38bcff775', )
            ]
        for cs_cls, exp_mac, exp_cdata in tests:
            # print(repr(cs_cls))
            # encrypt/mac
            cs = cs_cls(mac_key, enc_key, iv, header_len=3, aad_offset=1)
            hdr_mac_iv_cdata = cs.encrypt(data, header=header)
            hdr = hdr_mac_iv_cdata[0:3]
            mac = hdr_mac_iv_cdata[3:19]
            iv = hdr_mac_iv_cdata[19:31]
            cdata = hdr_mac_iv_cdata[31:]
            self.assert_equal(hexlify(hdr), b'123456')
            self.assert_equal(hexlify(mac), exp_mac)
            self.assert_equal(hexlify(iv), b'000000000000000000000000')
            self.assert_equal(hexlify(cdata), exp_cdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth/decrypt
            cs = cs_cls(mac_key, enc_key, header_len=len(header), aad_offset=1)
            pdata = cs.decrypt(hdr_mac_iv_cdata)
            self.assert_equal(data, pdata)
            self.assert_equal(cs.next_iv(), 1)
            # auth-failure due to corruption (corrupted aad)
            cs = cs_cls(mac_key, enc_key, header_len=len(header), aad_offset=1)
            hdr_mac_iv_cdata_corrupted = hdr_mac_iv_cdata[:1] + b'\0' + hdr_mac_iv_cdata[2:]
            self.assert_raises(IntegrityError,
                               lambda: cs.decrypt(hdr_mac_iv_cdata_corrupted))

    def test_hmac_sha256(self):
        # RFC 4231 test vectors
        key = b'\x0b' * 20
        # Also test that this works with memory views
        data = memoryview(unhexlify('4869205468657265'))
        hmac = unhexlify('b0344c61d8db38535ca8afceaf0bf12b'
                         '881dc200c9833da726e9376c2e32cff7')
        assert hmac_sha256(key, data) == hmac
        key = unhexlify('4a656665')
        data = unhexlify('7768617420646f2079612077616e7420'
                         '666f72206e6f7468696e673f')
        hmac = unhexlify('5bdcc146bf60754e6a042426089575c7'
                         '5a003f089d2739839dec58b964ec3843')
        assert hmac_sha256(key, data) == hmac
        key = b'\xaa' * 20
        data = b'\xdd' * 50
        hmac = unhexlify('773ea91e36800e46854db8ebd09181a7'
                         '2959098b3ef8c122d9635514ced565fe')
        assert hmac_sha256(key, data) == hmac
        key = unhexlify('0102030405060708090a0b0c0d0e0f10'
                        '111213141516171819')
        data = b'\xcd' * 50
        hmac = unhexlify('82558a389a443c0ea4cc819899f2083a'
                         '85f0faa3e578f8077a2e3ff46729665b')
        assert hmac_sha256(key, data) == hmac

    def test_blake2b_256(self):
        # In BLAKE2 the output length actually is part of the hashes personality - it is *not* simple truncation like in
        # the SHA-2 family. Therefore we need to generate test vectors ourselves (as is true for most applications that
        # are not precisely vanilla BLAKE2b-512 or BLAKE2s-256).
        #
        # Obtained via "b2sum" utility from the official BLAKE2 repository. It calculates the exact hash of a file's
        # contents, no extras (like length) included.
        assert blake2b_256(b'', b'abc') == unhexlify('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
        assert blake2b_256(b'a', b'bc') == unhexlify('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
        assert blake2b_256(b'ab', b'c') == unhexlify('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
        assert blake2b_256(b'abc', b'') == unhexlify('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')

        key = unhexlify('e944973af2256d4d670c12dd75304c319f58f4e40df6fb18ef996cb47e063676')
        data = memoryview(b'1234567890' * 100)
        assert blake2b_256(key, data) == unhexlify('97ede832378531dd0f4c668685d166e797da27b47d8cd441e885b60abd5e0cb2')

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
