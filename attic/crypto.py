import sys
from ctypes import cdll, c_char_p, c_int, c_uint, c_void_p, POINTER, create_string_buffer
from ctypes.util import find_library
import struct

libcrypto = cdll.LoadLibrary(find_library('crypto'))
# Default libcrypto on OS X is too old, try the brew version
if not hasattr(libcrypto, 'PKCS5_PBKDF2_HMAC') and sys.platform == 'darwin':
    libcrypto = cdll.LoadLibrary('/usr/local/opt/openssl/lib/libcrypto.dylib')
if not hasattr(libcrypto, 'PKCS5_PBKDF2_HMAC') and sys.platform.startswith('freebsd'):
    libcrypto = cdll.LoadLibrary('/usr/local/lib/libcrypto.so')
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
