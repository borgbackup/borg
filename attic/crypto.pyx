"""A thin OpenSSL wrapper

This could be replaced by PyCrypto or something similar when the performance
of their PBKDF2 implementation is comparable to the OpenSSL version.
"""
from libc.stdlib cimport malloc, free

API_VERSION = 2

TAG_SIZE = 16  # bytes; 128 bits is the maximum allowed value. see "hack" below.
IV_SIZE = 16  # bytes; 128 bits

cdef extern from "openssl/rand.h":
    int  RAND_bytes(unsigned char *buf, int num)


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
    const EVP_CIPHER *EVP_aes_256_gcm()
    void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a)
    void EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a)

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
    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, unsigned char *ptr)
    int PKCS5_PBKDF2_HMAC(const char *password, int passwordlen,
                          const unsigned char *salt, int saltlen, int iter,
                          const EVP_MD *digest,
                          int keylen, unsigned char *out)
    int EVP_CTRL_GCM_GET_TAG
    int EVP_CTRL_GCM_SET_TAG
    int EVP_CTRL_GCM_SET_IVLEN

import struct

_int = struct.Struct('>I')
_long = struct.Struct('>Q')

bytes_to_int = lambda x, offset=0: _int.unpack_from(x, offset)[0]
bytes_to_long = lambda x, offset=0: _long.unpack_from(x, offset)[0]
long_to_bytes = lambda x: _long.pack(x)


def num_aes_blocks(length):
    """Return the number of AES blocks required to encrypt/decrypt *length* bytes of data.
       Note: this is only correct for modes without padding, like AES-CTR.
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
    cdef int is_encrypt

    def __cinit__(self, is_encrypt, key, iv=None):
        EVP_CIPHER_CTX_init(&self.ctx)
        self.is_encrypt = is_encrypt
        # Set cipher type and mode
        cipher_mode = EVP_aes_256_gcm()
        if self.is_encrypt:
            if not EVP_EncryptInit_ex(&self.ctx, cipher_mode, NULL, NULL, NULL):
                raise Exception('EVP_EncryptInit_ex failed')
        else:  # decrypt
            if not EVP_DecryptInit_ex(&self.ctx, cipher_mode, NULL, NULL, NULL):
                raise Exception('EVP_DecryptInit_ex failed')
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
        # Set IV length (bytes)
        if not EVP_CIPHER_CTX_ctrl(&self.ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL):
            raise Exception('EVP_CIPHER_CTX_ctrl SET IVLEN failed')
        # Initialise key and IV
        if self.is_encrypt:
            if not EVP_EncryptInit_ex(&self.ctx, NULL, NULL, key2, iv2):
                raise Exception('EVP_EncryptInit_ex failed')
        else:  # decrypt
            if not EVP_DecryptInit_ex(&self.ctx, NULL, NULL, key2, iv2):
                raise Exception('EVP_DecryptInit_ex failed')

    def add(self, aad):
        cdef int aadl = len(aad)
        cdef int outl
        # Zero or more calls to specify any AAD
        if self.is_encrypt:
            if not EVP_EncryptUpdate(&self.ctx, NULL, &outl, aad, aadl):
                raise Exception('EVP_EncryptUpdate failed')
        else:  # decrypt
            if not EVP_DecryptUpdate(&self.ctx, NULL, &outl, aad, aadl):
                raise Exception('EVP_DecryptUpdate failed')

    def compute_tag_and_encrypt(self, data):
        cdef int inl = len(data)
        cdef int ctl = 0
        cdef int outl = 0
        # note: modes that use padding, need up to one extra AES block (16B)
        cdef unsigned char *out = <unsigned char *>malloc(inl+16)
        cdef unsigned char *tag = <unsigned char *>malloc(TAG_SIZE)
        if not out:
            raise MemoryError
        try:
            if not EVP_EncryptUpdate(&self.ctx, out, &outl, data, inl):
                raise Exception('EVP_EncryptUpdate failed')
            ctl = outl
            if not EVP_EncryptFinal_ex(&self.ctx, out+ctl, &outl):
                raise Exception('EVP_EncryptFinal failed')
            ctl += outl
            # Get tag
            if not EVP_CIPHER_CTX_ctrl(&self.ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag):
                raise Exception('EVP_CIPHER_CTX_ctrl GET TAG failed')
            # hack: caller wants 32B tags (256b), so we give back that amount
            return (tag[:TAG_SIZE] + b'\x00'*16), out[:ctl]
        finally:
            free(tag)
            free(out)

    def check_tag_and_decrypt(self, tag, data):
        cdef int inl = len(data)
        cdef int ptl = 0
        cdef int outl = 0
        # note: modes that use padding, need up to one extra AES block (16B).
        # This is what the openssl docs say. I am not sure this is correct,
        # but OTOH it will not cause any harm if our buffer is a little bigger.
        cdef unsigned char *out = <unsigned char *>malloc(inl+16)
        if not out:
            raise MemoryError
        try:
            if not EVP_DecryptUpdate(&self.ctx, out, &outl, data, inl):
                raise Exception('EVP_DecryptUpdate failed')
            ptl = outl
            # Set expected tag value.
            if not EVP_CIPHER_CTX_ctrl(&self.ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag):
                raise Exception('EVP_CIPHER_CTX_ctrl SET TAG failed')
            if EVP_DecryptFinal_ex(&self.ctx, out+ptl, &outl) <= 0:
                # a failure here means corrupted / tampered tag or data
                raise Exception('EVP_DecryptFinal failed')
            ptl += outl
            return out[:ptl]
        finally:
            free(out)
