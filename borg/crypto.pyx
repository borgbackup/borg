"""A thin OpenSSL wrapper

This could be replaced by PyCrypto maybe?
"""
import hashlib
import hmac
from math import ceil

from libc.stdlib cimport malloc, free

API_VERSION = '1.0_01'

cdef extern from "openssl/rand.h":
    int  RAND_bytes(unsigned char *buf, int num)


cdef extern from "openssl/evp.h":
    ctypedef struct EVP_MD:
        pass
    ctypedef struct EVP_CIPHER:
        pass
    ctypedef struct EVP_CIPHER_CTX:
        pass
    ctypedef struct ENGINE:
        pass
    const EVP_CIPHER *EVP_aes_256_ctr()
    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new()
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a)

    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                           const unsigned char *key, const unsigned char *iv)
    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
                           const unsigned char *key, const unsigned char *iv)
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                          const unsigned char *in_, int inl)
    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                          const unsigned char *in_, int inl)
    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)


import struct

_int = struct.Struct('>I')
_long = struct.Struct('>Q')
_2long = struct.Struct('>QQ')

bytes_to_int = lambda x, offset=0: _int.unpack_from(x, offset)[0]
bytes_to_long = lambda x, offset=0: _long.unpack_from(x, offset)[0]
long_to_bytes = lambda x: _long.pack(x)


def bytes16_to_int(b, offset=0):
    h, l = _2long.unpack_from(b, offset)
    return (h << 64) + l


def int_to_bytes16(i):
    max_uint64 = 0xffffffffffffffff
    l = i & max_uint64
    h = (i >> 64) & max_uint64
    return _2long.pack(h, l)


def increment_iv(iv, amount=1):
    """
    Increment the IV by the given amount (default 1).

    :param iv: input IV, 16 bytes (128 bit)
    :param amount: increment value
    :return: input_IV + amount, 16 bytes (128 bit)
    """
    assert len(iv) == 16
    iv = bytes16_to_int(iv)
    iv += amount
    iv = int_to_bytes16(iv)
    return iv


def num_aes_blocks(int length):
    """Return the number of AES blocks required to encrypt/decrypt *length* bytes of data.
       Note: this is only correct for modes without padding, like AES-CTR.
    """
    return (length + 15) // 16


cdef class AES:
    """A thin wrapper around the OpenSSL EVP cipher API
    """
    cdef EVP_CIPHER_CTX *ctx
    cdef int is_encrypt
    cdef unsigned char iv_orig[16]
    cdef long long blocks

    def __cinit__(self, is_encrypt, key, iv=None):
        self.ctx = EVP_CIPHER_CTX_new()
        self.is_encrypt = is_encrypt
        # Set cipher type and mode
        cipher_mode = EVP_aes_256_ctr()
        if self.is_encrypt:
            if not EVP_EncryptInit_ex(self.ctx, cipher_mode, NULL, NULL, NULL):
                raise Exception('EVP_EncryptInit_ex failed')
        else:  # decrypt
            if not EVP_DecryptInit_ex(self.ctx, cipher_mode, NULL, NULL, NULL):
                raise Exception('EVP_DecryptInit_ex failed')
        self.reset(key, iv)

    def __dealloc__(self):
        EVP_CIPHER_CTX_free(self.ctx)

    def reset(self, key=None, iv=None):
        cdef const unsigned char *key2 = NULL
        cdef const unsigned char *iv2 = NULL
        if key:
            key2 = key
        if iv:
            iv2 = iv
            assert isinstance(iv, bytes) and len(iv) == 16
            for i in range(16):
                self.iv_orig[i] = iv[i]
            self.blocks = 0  # number of AES blocks encrypted starting with iv_orig
        # Initialise key and IV
        if self.is_encrypt:
            if not EVP_EncryptInit_ex(self.ctx, NULL, NULL, key2, iv2):
                raise Exception('EVP_EncryptInit_ex failed')
        else:  # decrypt
            if not EVP_DecryptInit_ex(self.ctx, NULL, NULL, key2, iv2):
                raise Exception('EVP_DecryptInit_ex failed')

    @property
    def iv(self):
        return increment_iv(self.iv_orig[:16], self.blocks)

    def encrypt(self, data):
        cdef int inl = len(data)
        cdef int ctl = 0
        cdef int outl = 0
        # note: modes that use padding, need up to one extra AES block (16b)
        cdef unsigned char *out = <unsigned char *>malloc(inl+16)
        if not out:
            raise MemoryError
        try:
            if not EVP_EncryptUpdate(self.ctx, out, &outl, data, inl):
                raise Exception('EVP_EncryptUpdate failed')
            ctl = outl
            if not EVP_EncryptFinal_ex(self.ctx, out+ctl, &outl):
                raise Exception('EVP_EncryptFinal failed')
            ctl += outl
            self.blocks += num_aes_blocks(ctl)
            return out[:ctl]
        finally:
            free(out)

    def decrypt(self, data):
        cdef int inl = len(data)
        cdef int ptl = 0
        cdef int outl = 0
        # note: modes that use padding, need up to one extra AES block (16b).
        # This is what the openssl docs say. I am not sure this is correct,
        # but OTOH it will not cause any harm if our buffer is a little bigger.
        cdef unsigned char *out = <unsigned char *>malloc(inl+16)
        if not out:
            raise MemoryError
        try:
            if not EVP_DecryptUpdate(self.ctx, out, &outl, data, inl):
                raise Exception('EVP_DecryptUpdate failed')
            ptl = outl
            if EVP_DecryptFinal_ex(self.ctx, out+ptl, &outl) <= 0:
                # this error check is very important for modes with padding or
                # authentication. for them, a failure here means corrupted data.
                # CTR mode does not use padding nor authentication.
                raise Exception('EVP_DecryptFinal failed')
            ptl += outl
            self.blocks += num_aes_blocks(inl)
            return out[:ptl]
        finally:
            free(out)


def hkdf_hmac_sha512(ikm, salt, info, output_length):
    """
    Compute HKDF-HMAC-SHA512 with input key material *ikm*, *salt* and *info* to produce *output_length* bytes.

    This is the "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)" (RFC 5869)
    instantiated with HMAC-SHA512.

    *output_length* must not be greater than 64 * 255 bytes.
    """
    digest_length = 64
    assert output_length <= (255 * digest_length), 'output_length must be <= 255 * 64 bytes'
    # Step 1. HKDF-Extract (ikm, salt) -> prk
    if salt is None:
        salt = bytes(64)
    prk = hmac.HMAC(salt, ikm, hashlib.sha512).digest()

    # Step 2. HKDF-Expand (prk, info, output_length) -> output key
    n = ceil(output_length / digest_length)
    t_n = b''
    output = b''
    for i in range(n):
        msg = t_n + info + (i + 1).to_bytes(1, 'little')
        t_n = hmac.HMAC(prk, msg, hashlib.sha512).digest()
        output += t_n
    return output[:output_length]
