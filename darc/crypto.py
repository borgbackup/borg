from binascii import hexlify
from ctypes import cdll, c_char_p, c_int, c_uint, c_void_p, byref, POINTER, create_string_buffer
from ctypes.util import find_library
import struct
import unittest

libcrypto = cdll.LoadLibrary(find_library('crypto'))
libcrypto.PKCS5_PBKDF2_HMAC.argtypes = (c_char_p, c_int, c_char_p, c_int, c_int, c_void_p, c_int, c_char_p)
libcrypto.EVP_sha256.restype = c_void_p
libcrypto.AES_set_encrypt_key.argtypes = (c_char_p, c_int, c_char_p)
libcrypto.AES_ctr128_encrypt.argtypes = (c_char_p, c_char_p, c_int, c_char_p, c_char_p, c_char_p, POINTER(c_uint))

_int = struct.Struct('>I')
_long = struct.Struct('>Q')

bytes_to_int = lambda x, offset=0: _int.unpack_from(x, offset)[0]
bytes_to_long = lambda x, offset=0: _long.unpack_from(x, offset)[0]
long_to_bytes = lambda x: _long.pack(x)


def pbkdf2_sha256(password, salt, iterations, size):
    key = create_string_buffer(size)
    rv = libcrypto.PKCS5_PBKDF2_HMAC(password, len(password), salt, len(salt), iterations, libcrypto.EVP_sha256(), size, key)
    if not rv:
        raise Exception('PKCS5_PBKDF2_HMAC failed')
    return key.raw


def get_random_bytes(n):
    """Return n cryptographically strong pseudo-random bytes
    """
    buf = create_string_buffer(n)
    if not libcrypto.RAND_bytes(buf, n):
        raise Exception('RAND_bytes failed')
    return buf.raw


class AES:
    def __init__(self, key, iv=None):
        self.key = create_string_buffer(2000)
        self.iv = create_string_buffer(16)
        self.buf = create_string_buffer(16)
        self.num = c_uint()
        self.reset(key, iv)

    def reset(self, key=None, iv=None):
        if key:
            libcrypto.AES_set_encrypt_key(key, len(key) * 8, self.key)
        if iv:
            self.iv.raw = iv
        self.num.value = 0

    def encrypt(self, data):
        out = create_string_buffer(len(data))
        libcrypto.AES_ctr128_encrypt(data, out, len(data), self.key, self.iv, self.buf, self.num)
        return out.raw
    decrypt = encrypt


class CryptoTestCase(unittest.TestCase):

    def test_bytes_to_int(self):
        self.assertEqual(bytes_to_int(b'\0\0\0\1'), 1)

    def test_bytes_to_long(self):
        self.assertEqual(bytes_to_long(b'\0\0\0\0\0\0\0\1'), 1)
        self.assertEqual(long_to_bytes(1), b'\0\0\0\0\0\0\0\1')

    def test_pbkdf2_sha256(self):
        self.assertEqual(hexlify(pbkdf2_sha256(b'password', b'salt', 1, 32)),
                         b'120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
        self.assertEqual(hexlify(pbkdf2_sha256(b'password', b'salt', 2, 32)),
                         b'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43')
        self.assertEqual(hexlify(pbkdf2_sha256(b'password', b'salt', 4096, 32)),
                         b'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a')

    def test_get_random_bytes(self):
        bytes = get_random_bytes(10)
        bytes2 = get_random_bytes(10)
        self.assertEqual(len(bytes), 10)
        self.assertEqual(len(bytes2), 10)
        self.assertNotEqual(bytes, bytes2)

    def test_aes(self):
        key = b'X' * 32
        data = b'foo' * 10
        aes = AES(key)
        self.assertEqual(bytes_to_long(aes.iv.raw, 8), 0)
        cdata = aes.encrypt(data)
        self.assertEqual(hexlify(cdata), b'c6efb702de12498f34a2c2bbc8149e759996d08bf6dc5c610aefc0c3a466')
        self.assertEqual(bytes_to_long(aes.iv.raw, 8), 2)
        self.assertNotEqual(data, aes.decrypt(cdata))
        aes.reset(iv=b'\0' * 16)
        self.assertEqual(data, aes.decrypt(cdata))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(CryptoTestCase)

if __name__ == '__main__':
    unittest.main()