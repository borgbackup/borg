from binascii import hexlify, unhexlify

from ..crypto import AES, bytes_to_long, bytes_to_int, long_to_bytes, hmac_sha256
from . import BaseTestCase

# Note: these tests are part of the self test, do not use or import py.test functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT


class CryptoTestCase(BaseTestCase):

    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes_to_long(self):
        self.assert_equal(bytes_to_long(b'\0\0\0\0\0\0\0\1'), 1)
        self.assert_equal(long_to_bytes(1), b'\0\0\0\0\0\0\0\1')

    def test_aes(self):
        key = b'X' * 32
        data = b'foo' * 10
        # encrypt
        aes = AES(is_encrypt=True, key=key)
        self.assert_equal(bytes_to_long(aes.iv, 8), 0)
        cdata = aes.encrypt(data)
        self.assert_equal(hexlify(cdata), b'c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466')
        self.assert_equal(bytes_to_long(aes.iv, 8), 2)
        # decrypt
        aes = AES(is_encrypt=False, key=key)
        self.assert_equal(bytes_to_long(aes.iv, 8), 0)
        pdata = aes.decrypt(cdata)
        self.assert_equal(data, pdata)
        self.assert_equal(bytes_to_long(aes.iv, 8), 2)

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
