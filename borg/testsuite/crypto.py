from binascii import hexlify

from ..crypto import AES, bytes_to_long, bytes_to_int, long_to_bytes
from . import BaseTestCase


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
