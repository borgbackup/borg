"""A thin OpenSSL wrapper

This could be replaced by PyCrypto or something similar when the performance
of their PBKDF2 implementation is comparable to the OpenSSL version.
"""
from libc.string cimport memcpy
from libc.stdlib cimport malloc, free

API_VERSION = 1

cdef extern from "openssl/rand.h":
    int  RAND_bytes(unsigned char *buf,int num)

cdef extern from "openssl/aes.h":
    ctypedef struct AES_KEY:
        pass

    int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
    void AES_ctr128_encrypt(const unsigned char *in_, unsigned char *out,
                            size_t length, const AES_KEY *key,
                            unsigned char *ivec,
                            unsigned char *ecount_buf,
                            unsigned int *num)

cdef extern from "openssl/evp.h":
    ctypedef struct EVP_MD:
        pass
    const EVP_MD *EVP_sha256()
    int PKCS5_PBKDF2_HMAC(const char *password, int passwordlen,
                          const unsigned char *salt, int saltlen, int iter,
                          const EVP_MD *digest,
                          int keylen, unsigned char *out)

import struct

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
    cdef unsigned char *key = <unsigned char *>malloc(size)
    if not key:
        raise MemoryError
    try:
        rv = PKCS5_PBKDF2_HMAC(password, len(password), salt, len(salt), iterations, EVP_sha256(), size, key)
        if not rv:
            raise Exception('PKCS5_PBKDF2_HMAC failed')
        return key[:size]
    finally:
        free(key)


def get_random_bytes(n):
    """Return n cryptographically strong pseudo-random bytes
    """
    cdef unsigned char *buf = <unsigned char *>malloc(n)
    if not buf:
        raise MemoryError
    try:
        if RAND_bytes(buf, n) < 1:
            raise Exception('RAND_bytes failed')
        return buf[:n]
    finally:
        free(buf)


cdef class AES:
    """A thin wrapper around the OpenSSL AES CTR_MODE cipher
    """
    cdef AES_KEY key
    cdef unsigned char _iv[16]
    cdef unsigned char buf[16]
    cdef unsigned int num

    def __cinit__(self, key, iv=None):
        self.reset(key, iv)

    def reset(self, key=None, iv=None):
        if key:
            AES_set_encrypt_key(key, len(key) * 8, &self.key)
        if iv:
            memcpy(self._iv, <unsigned char *>iv, 16)
        self.num = 0

    @property
    def iv(self):
        return self._iv[:16]

    def encrypt(self, data):
        cdef int n = len(data)
        cdef unsigned char *out = <unsigned char *>malloc(n)
        if not out:
            raise MemoryError
        try:
            AES_ctr128_encrypt(data, out, len(data), &self.key, self._iv, self.buf, &self.num)
            return out[:n]
        finally:
            free(out)
    decrypt = encrypt

