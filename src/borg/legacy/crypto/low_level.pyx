from cpython cimport PyMem_Malloc, PyMem_Free
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release

from ..crypto.low_level import num_cipher_blocks


cdef extern from "openssl/evp.h":
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


ctypedef const EVP_CIPHER * (* CIPHER)()


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


cdef class AES:
    """A thin wrapper around the OpenSSL EVP cipher API - for legacy key file encryption."""
    cdef CIPHER cipher
    cdef EVP_CIPHER_CTX *ctx
    cdef unsigned char enc_key[32]
    cdef int cipher_blk_len
    cdef int iv_len
    cdef unsigned char iv[16]
    cdef long long blocks

    def __init__(self, enc_key, iv=None):
        assert isinstance(enc_key, bytes) and len(enc_key) == 32
        self.enc_key = enc_key
        self.iv_len = 16
        assert sizeof(self.iv) == self.iv_len
        self.cipher = EVP_aes_256_ctr
        self.cipher_blk_len = 16
        if iv is not None:
            self.set_iv(iv)
        else:
            self.blocks = -1  # make sure set_iv is called before encrypt

    def __cinit__(self, enc_key, iv=None):
        self.ctx = EVP_CIPHER_CTX_new()

    def __dealloc__(self):
        EVP_CIPHER_CTX_free(self.ctx)

    def encrypt(self, data, iv=None):
        if iv is not None:
            self.set_iv(iv)
        assert self.blocks == 0, 'iv needs to be set before encrypt is called'
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int ilen = len(data)
        cdef int olen = 0
        cdef int offset

        try:
            odata = <unsigned char *>PyMem_Malloc(ilen + self.cipher_blk_len)
            if not odata:
                raise MemoryError

            idata = ro_buffer(data)
            idata_acquired = True

            if not EVP_EncryptInit_ex(self.ctx, self.cipher(), NULL, self.enc_key, self.iv):
                raise Exception('EVP_EncryptInit_ex failed')
            offset = 0
            if not EVP_EncryptUpdate(self.ctx, odata, &olen, <const unsigned char*> idata.buf, ilen):
                raise Exception('EVP_EncryptUpdate failed')
            offset += olen
            if not EVP_EncryptFinal_ex(self.ctx, odata+offset, &olen):
                raise Exception('EVP_EncryptFinal failed')
            offset += olen
            self.blocks = self.block_count(offset)
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
            if idata_acquired:
                PyBuffer_Release(&idata)

    def decrypt(self, data):
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int ilen = len(data)
        cdef int offset
        cdef int olen = 0

        try:
            odata = <unsigned char *>PyMem_Malloc(ilen + self.cipher_blk_len)
            if not odata:
                raise MemoryError

            idata = ro_buffer(data)
            idata_acquired = True

            if not EVP_DecryptInit_ex(self.ctx, self.cipher(), NULL, self.enc_key, self.iv):
                raise Exception('EVP_DecryptInit_ex failed')
            offset = 0
            if not EVP_DecryptUpdate(self.ctx, odata, &olen, <const unsigned char*> idata.buf, ilen):
                raise Exception('EVP_DecryptUpdate failed')
            offset += olen
            if not EVP_DecryptFinal_ex(self.ctx, odata+offset, &olen):
                raise Exception('EVP_DecryptFinal failed')
            offset += olen
            self.blocks = self.block_count(ilen)
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
            if idata_acquired:
                PyBuffer_Release(&idata)

    def block_count(self, length):
        return num_cipher_blocks(length, self.cipher_blk_len)

    def set_iv(self, iv):
        if isinstance(iv, int):
            iv = iv.to_bytes(self.iv_len, byteorder='big')
        assert isinstance(iv, bytes) and len(iv) == self.iv_len
        self.iv = iv
        self.blocks = 0

    def next_iv(self):
        iv = int.from_bytes(self.iv[:self.iv_len], byteorder='big')
        return iv + self.blocks
