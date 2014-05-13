"""A thin OpenSSL wrapper

This could be replaced by PyCrypto or something similar when the performance
of their PBKDF2 implementation is comparable to the OpenSSL version.
"""
from libc.stdlib cimport malloc, free

API_VERSION = 2

cdef extern from "openssl/rand.h":
    int  RAND_bytes(unsigned char *buf,int num)


cdef extern from "openssl/evp.h":
    ctypedef struct EVP_MD:
        pass
    ctypedef struct EVP_CIPHER:
        pass
    ctypedef struct EVP_CIPHER_CTX:
        unsigned char *iv
        pass
    ctypedef struct ENGINE:
        pass
    const EVP_MD *EVP_sha256()
    const EVP_CIPHER *EVP_aes_256_ctr()
    void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a)
    void EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a)

    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                           const unsigned char *key, const unsigned char *iv)
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          int *outl, const unsigned char *in_, int inl)

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
    """A thin wrapper around the OpenSSL EVP cipher API
    """
    cdef EVP_CIPHER_CTX ctx

    def __cinit__(self, key, iv=None):
        EVP_CIPHER_CTX_init(&self.ctx)
        if not EVP_EncryptInit_ex(&self.ctx, EVP_aes_256_ctr(), NULL, NULL, NULL):
            raise Exception('EVP_EncryptInit_ex failed')
        self.reset(key, iv)

    def __dealloc__(self):
        EVP_CIPHER_CTX_cleanup(&self.ctx)

    def reset(self, key=None, iv=None):
        cdef const unsigned char *key2 = NULL
        cdef const unsigned char *iv2 = NULL
        if key:
            key2 = key
        if iv:
            iv2 = iv
        if not EVP_EncryptInit_ex(&self.ctx, NULL, NULL, key2, iv2):
            raise Exception('EVP_EncryptInit_ex failed')

    @property
    def iv(self):
        return self.ctx.iv[:16]

    def encrypt(self, data):
        cdef int inl = len(data)
        cdef int outl
        cdef unsigned char *out = <unsigned char *>malloc(inl)
        if not out:
            raise MemoryError
        try:
            if not EVP_EncryptUpdate(&self.ctx, out, &outl, data, inl):
                raise Exception('EVP_EncryptUpdate failed')
            return out[:inl]
        finally:
            free(out)
    decrypt = encrypt

