from binascii import hexlify

from ..crypto import AES, bytes_to_long, bytes_to_int, long_to_bytes
from ..crypto import increment_iv, bytes16_to_int, int_to_bytes16
from . import BaseTestCase


class CryptoTestCase(BaseTestCase):

    def test_bytes_to_int(self):
        self.assert_equal(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes_to_long(self):
        self.assert_equal(bytes_to_long(b'\0\0\0\0\0\0\0\1'), 1)
        self.assert_equal(long_to_bytes(1), b'\0\0\0\0\0\0\0\1')

    def test_bytes16_to_int(self):
        self.assert_equal(bytes16_to_int(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1'), 1)
        self.assert_equal(int_to_bytes16(1), b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
        self.assert_equal(bytes16_to_int(b'\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0'), 2 ** 64)
        self.assert_equal(int_to_bytes16(2 ** 64), b'\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0')

    def test_increment_iv(self):
        iv0 = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        iv1 = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1'
        iv2 = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\2'
        self.assert_equal(increment_iv(iv0, 0), iv0)
        self.assert_equal(increment_iv(iv0, 1), iv1)
        self.assert_equal(increment_iv(iv0, 2), iv2)
        iva = b'\0\0\0\0\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff'
        ivb = b'\0\0\0\0\0\0\0\1\x00\x00\x00\x00\x00\x00\x00\x00'
        ivc = b'\0\0\0\0\0\0\0\1\x00\x00\x00\x00\x00\x00\x00\x01'
        self.assert_equal(increment_iv(iva, 0), iva)
        self.assert_equal(increment_iv(iva, 1), ivb)
        self.assert_equal(increment_iv(iva, 2), ivc)
        self.assert_equal(increment_iv(iv0, 2**64), ivb)

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
