"""A thin ctypes based wrapper for OpenSSL 1.0
"""
import os
from ctypes import cdll, c_char_p, c_int, c_uint, c_void_p, POINTER, create_string_buffer
from ctypes.util import find_library
import struct


def _find_libcrypto():
    _possible_paths = [
        find_library('crypto'),
        os.environ.get('ATTIC_LIBCRYPTO_PATH'),
        '/usr/local/opt/openssl/lib/libcrypto.dylib',  # OS X Brew
        '/usr/local/lib/libcrypto.so',                 # FreeBSD Ports
        '/usr/local/ssl/lib/libcrypto.so'
    ]
    for path in _possible_paths:
        try:
            lib = cdll.LoadLibrary(path)
            if hasattr(lib, 'PKCS5_PBKDF2_HMAC'):
                return lib
        except OSError:
            pass
    raise Exception('Failed to find libcrypto version >= 1.0')

libcrypto = _find_libcrypto()

libcrypto.PKCS5_PBKDF2_HMAC.argtypes = (c_char_p, c_int, c_char_p, c_int, c_int, c_void_p, c_int, c_char_p)
libcrypto.EVP_sha256.restype = c_void_p
libcrypto.AES_set_encrypt_key.argtypes = (c_char_p, c_int, c_char_p)
libcrypto.AES_ctr128_encrypt.argtypes = (c_char_p, c_char_p, c_int, c_char_p, c_char_p, c_char_p, POINTER(c_uint))
libcrypto.RAND_bytes.argtypes = (c_char_p, c_int)
libcrypto.RAND_bytes.restype = c_int

_int = struct.Struct('>I')
_long = struct.Struct('>Q')

bytes_to_int = lambda x, offset=0: _int.unpack_from(x, offset)[0]
bytes_to_long = lambda x, offset=0: _long.unpack_from(x, offset)[0]
long_to_bytes = lambda x: _long.pack(x)


def num_aes_blocks(length):
    """Return the number of AES blocks required to encrypt/decrypt *length* bytes of data
    """
    return (length + 15) // 16


def pbkdf2_sha256(password, salt, iterations, size):
    """Password based key derivation function 2 (RFC2898)
    """
    key = create_string_buffer(size)
    rv = libcrypto.PKCS5_PBKDF2_HMAC(password, len(password), salt, len(salt), iterations, libcrypto.EVP_sha256(), size, key)
    if not rv:
        raise Exception('PKCS5_PBKDF2_HMAC failed')
    return key.raw


def get_random_bytes(n):
    """Return n cryptographically strong pseudo-random bytes
    """
    buf = create_string_buffer(n)
    if libcrypto.RAND_bytes(buf, n) < 1:
        raise Exception('RAND_bytes failed')
    return buf.raw


class AES:
    """A thin wrapper around the OpenSSL AES CTR_MODE cipher
    """
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
