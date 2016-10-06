"""A thin OpenSSL wrapper"""

import hashlib
import hmac
import io

from libc.stdlib cimport malloc, free
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release

API_VERSION = 4


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
    md = bytes(32)
    cdef Py_buffer data_buf = ro_buffer(data)
    cdef const unsigned char *key_ptr = key
    cdef int key_len = len(key)
    cdef unsigned char *md_ptr = md
    try:
        with nogil:
            rc = HMAC(EVP_sha256(), key_ptr, key_len, <const unsigned char*> data_buf.buf, data_buf.len, md_ptr, NULL)
        if rc != md_ptr:
            raise Exception('HMAC(EVP_sha256) failed')
    finally:
        PyBuffer_Release(&data_buf)
    return md


class FileLikeWrapper:
    def __enter__(self):
        self.fd.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fd.__exit__(exc_type, exc_val, exc_tb)

    def tell(self):
        return self.fd.tell()

    def seek(self, offset, whence=io.SEEK_SET):
        return self.fd.seek(offset, whence)

    def write(self, data):
        self.fd.write(data)

    def read(self, n=None):
        return self.fd.read(n)


class StreamSigner(FileLikeWrapper):
    """
    Wrapper for file-like objects that computes a signature or digest.

    WARNING: Seeks should only be used to query the size of the file, not
    to skip data, because skipped data isn't read and not signed.

    Note: When used as a context manager read/write operations outside the enclosed scope
    are illegal.
    """

    def __init__(self, key, backing_fd, write):
        self.fd = backing_fd
        self.writing = write

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.sign_length()
        super().__exit__(exc_type, exc_val, exc_tb)

    def write(self, data):
        """
        Write *data* to backing file and update internal state.
        """
        self.fd.write(data)
        self.update(data)

    def read(self, n=None):
        """
        Read *data* from backing file (*n* has the usual meaning) and update internal state.
        """
        data = self.fd.read(n)
        self.update(data)
        return data

    def signature(self):
        """
        Return current signature bytestring.

        Note: this can be called multiple times.
        """
        raise NotImplementedError

    def update(self, data):
        """
        Update internal state with *data*.
        """
        raise NotImplementedError

    def sign_length(self, seek_to_end=False):
        if seek_to_end:
            # Sign length of file as well to avoid problems if only a prefix is read.
            self.seek(0, io.SEEK_END)
        self.update(str(self.tell()).encode())


class StreamSigner_HMAC_SHA512(StreamSigner):
    NAME = 'HMAC_SHA_512'

    def __init__(self, key, backing_fd, write):
        super().__init__(key, backing_fd, write)
        self.hmac = hmac.new(key, digestmod=hashlib.sha512)

    def update(self, data):
        self.hmac.update(data)

    def signature(self):
        return self.hmac.digest()
