# cython: language_level=3

"""A thin OpenSSL wrapper"""

import hashlib
import hmac
from math import ceil

from libc.stdlib cimport malloc, free
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize

API_VERSION = '1.1_02'


cdef extern from "../algorithms/blake2-libselect.h":
    ctypedef struct blake2b_state:
        pass

    int blake2b_init(blake2b_state *S, size_t outlen) nogil
    int blake2b_update(blake2b_state *S, const void *input, size_t inlen) nogil
    int blake2b_final(blake2b_state *S, void *out, size_t outlen) nogil


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

    EVP_MD *EVP_sha256() nogil


cdef extern from "openssl/hmac.h":
    unsigned char *HMAC(const EVP_MD *evp_md,
                    const void *key, int key_len,
                    const unsigned char *data, int data_len,
                    unsigned char *md, unsigned int *md_len) nogil

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


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


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
        cdef Py_buffer data_buf = ro_buffer(data)
        cdef int inl = len(data)
        cdef int ctl = 0
        cdef int outl = 0
        # note: modes that use padding, need up to one extra AES block (16b)
        cdef unsigned char *out = <unsigned char *>malloc(inl+16)
        if not out:
            raise MemoryError
        try:
            if not EVP_EncryptUpdate(self.ctx, out, &outl, <const unsigned char*> data_buf.buf, inl):
                raise Exception('EVP_EncryptUpdate failed')
            ctl = outl
            if not EVP_EncryptFinal_ex(self.ctx, out+ctl, &outl):
                raise Exception('EVP_EncryptFinal failed')
            ctl += outl
            self.blocks += num_aes_blocks(ctl)
            return out[:ctl]
        finally:
            free(out)
            PyBuffer_Release(&data_buf)

    def decrypt(self, data):
        cdef Py_buffer data_buf = ro_buffer(data)
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
            if not EVP_DecryptUpdate(self.ctx, out, &outl, <const unsigned char*> data_buf.buf, inl):
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
            PyBuffer_Release(&data_buf)


def hmac_sha256(key, data):
    cdef Py_buffer data_buf = ro_buffer(data)
    cdef const unsigned char *key_ptr = key
    cdef int key_len = len(key)
    cdef unsigned char md[32]
    try:
        rc = HMAC(EVP_sha256(), key_ptr, key_len, <const unsigned char*> data_buf.buf, data_buf.len, md, NULL)
        if rc != md:
            raise Exception('HMAC(EVP_sha256) failed')
    finally:
        PyBuffer_Release(&data_buf)
    return PyBytes_FromStringAndSize(<char*> &md[0], 32)


cdef blake2b_update_from_buffer(blake2b_state *state, obj):
    cdef Py_buffer buf = ro_buffer(obj)
    try:
        rc = blake2b_update(state, buf.buf, buf.len)
        if rc == -1:
            raise Exception('blake2b_update() failed')
    finally:
        PyBuffer_Release(&buf)


def blake2b_256(key, data):
    cdef blake2b_state state
    if blake2b_init(&state, 32) == -1:
        raise Exception('blake2b_init() failed')

    cdef unsigned char md[32]
    cdef unsigned char *key_ptr = key

    # This is secure, because BLAKE2 is not vulnerable to length-extension attacks (unlike SHA-1/2, MD-5 and others).
    # See the BLAKE2 paper section 2.9 "Keyed hashing (MAC and PRF)" for details.
    # A nice benefit is that this simpler prefix-MAC mode has less overhead than the more complex HMAC mode.
    # We don't use the BLAKE2 parameter block (via blake2s_init_key) for this to
    # avoid incompatibility with the limited API of OpenSSL.
    rc = blake2b_update(&state, key_ptr, len(key))
    if rc == -1:
        raise Exception('blake2b_update() failed')
    blake2b_update_from_buffer(&state, data)

    rc = blake2b_final(&state, &md[0], 32)
    if rc == -1:
        raise Exception('blake2b_final() failed')

    return PyBytes_FromStringAndSize(<char*> &md[0], 32)


def blake2b_128(data):
    cdef blake2b_state state
    cdef unsigned char md[16]
    cdef unsigned char *data_ptr = data

    if blake2b_init(&state, 16) == -1:
        raise Exception('blake2b_init() failed')

    rc = blake2b_update(&state, data_ptr, len(data))
    if rc == -1:
        raise Exception('blake2b_update() failed')

    rc = blake2b_final(&state, &md[0], 16)
    if rc == -1:
        raise Exception('blake2b_final() failed')

    return PyBytes_FromStringAndSize(<char*> &md[0], 16)


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
