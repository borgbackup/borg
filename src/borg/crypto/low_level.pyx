"""An AEAD-style OpenSSL wrapper

API:

    encrypt(data, header=b'', iv=None, aad=b'') -> envelope
    decrypt(envelope, aad=b'') -> data

header_len and aad_offset are given to the ciphersuite class when creating it, see below.

Envelope layout:

|<--------------------------- envelope ------------------------------------------>|
|<------------ header ----------->|<---------- ciphersuite specific ------------->|
|<-- not auth data -->|<-- aad -->|<-- e.g.:  S(aad, iv, E(data)), iv, E(data) -->|

|--- #aad_offset ---->|
|------------- #header_len ------>|

S means a cryptographic signature function (like HMAC or GMAC).
E means an encryption function (like AES).
iv is the initialization vector / nonce, if needed.

The split of header into not-authenticated data and AAD (additional authenticated
data) is done to support the legacy envelope layout as used in Attic and early Borg
(where the TYPE byte was not authenticated) and avoid unneeded memcpy and string
garbage.

Newly designed envelope layouts can just authenticate the whole header.

IV handling (CS is one of the ciphersuite classes below - the AEAD ones take a single key,
the legacy AES-CTR ones a mac_key and an enc_key):

    iv = ...  # just never repeat!
    cs = CS(..., iv=iv, header_len=header_len, aad_offset=aad_offset)
    envelope = cs.encrypt(data, header=header)
    iv = cs.next_iv()
    (repeat)
"""

import hashlib
import hmac
from math import ceil

from cpython cimport PyMem_Malloc, PyMem_Free
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AsString
from libc.stdint cimport uint8_t, uint32_t, uint64_t
from libc.string cimport memset, memcpy



cdef extern from "openssl/crypto.h" nogil:
    int CRYPTO_memcmp(const void *a, const void *b, size_t len)

cdef extern from "openssl/opensslv.h":
    long OPENSSL_VERSION_NUMBER

cdef extern from "openssl/evp.h" nogil:
    ctypedef struct EVP_MD:
        pass
    ctypedef struct EVP_CIPHER:
        pass
    ctypedef struct EVP_CIPHER_CTX:
        pass
    ctypedef struct ENGINE:
        pass

    const EVP_CIPHER *EVP_aes_256_ctr()
    const EVP_CIPHER *EVP_aes_256_ocb()
    const EVP_CIPHER *EVP_chacha20_poly1305()

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

    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
    int EVP_CTRL_AEAD_GET_TAG
    int EVP_CTRL_AEAD_SET_TAG
    int EVP_CTRL_AEAD_SET_IVLEN


import struct

_int = struct.Struct('>I')
_long = struct.Struct('>Q')

bytes_to_int = lambda x, offset=0: _int.unpack_from(x, offset)[0]
bytes_to_long = lambda x, offset=0: _long.unpack_from(x, offset)[0]
long_to_bytes = lambda x: _long.pack(x)


def num_cipher_blocks(length, blocksize=16):
    """Return the number of cipher blocks required to encrypt/decrypt <length> bytes of data.

    For a precise computation, <blocksize> must be the used cipher's block size (AES: 16, CHACHA20: 64).

    For a safe-upper-boundary computation, <blocksize> must be the MINIMUM of the block sizes (in
    bytes) of ALL supported ciphers. This can be used to adjust a counter if the used cipher is not
    known (yet).
    The default value of blocksize must be adjusted so it reflects this minimum, so a call of this
    function without a blocksize is "safe-upper-boundary by default".

    Padding cipher modes are not supported.
    """
    return (length + blocksize - 1) // blocksize


class CryptoError(Exception):
    """Malfunction in the crypto module."""


class IntegrityError(CryptoError):
    """Integrity checks failed. Corrupted or tampered data."""


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


class UNENCRYPTED:
    # Layout: HEADER + PlainText

    def __init__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        assert mac_key is None
        assert enc_key is None
        self.header_len = header_len
        self.set_iv(iv)

    def encrypt(self, data, header=b'', iv=None, aad=None):
        """
        IMPORTANT: it is called encrypt to satisfy the crypto api naming convention,
        but this does NOT encrypt and it does NOT compute and store a MAC either.
        """
        if iv is not None:
            self.set_iv(iv)
        assert self.iv is not None, 'iv needs to be set before encrypt is called'
        return header + data

    def decrypt(self, envelope, aad=None):
        """
        IMPORTANT: it is called decrypt to satisfy the crypto api naming convention,
        but this does NOT decrypt and it does NOT verify a MAC either, because data
        is not encrypted and there is no MAC.
        """
        return memoryview(envelope)[self.header_len:]

    def block_count(self, length):
        return 0

    def set_iv(self, iv):
        self.iv = iv

    def next_iv(self):
        return self.iv

    def extract_iv(self, envelope):
        return 0


cdef class AES256_CTR_BASE:
    # Layout: HEADER + MAC 32 + IV 8 + CT (same as attic / borg < 2.0 IF HEADER = TYPE_BYTE, no AAD)

    cdef EVP_CIPHER_CTX *ctx
    cdef unsigned char enc_key[32]
    cdef int cipher_blk_len
    cdef int iv_len, iv_len_short
    cdef int aad_offset
    cdef int header_len
    cdef int mac_len
    cdef unsigned char iv[16]
    cdef long long blocks

    @classmethod
    def requirements_check(cls):
        pass

    def __init__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        self.requirements_check()
        assert isinstance(enc_key, bytes) and len(enc_key) == 32
        self.cipher_blk_len = 16
        self.iv_len = sizeof(self.iv)
        self.iv_len_short = 8
        assert aad_offset <= header_len
        self.aad_offset = aad_offset
        self.header_len = header_len
        self.mac_len = 32
        self.enc_key = enc_key
        if iv is not None:
            self.set_iv(iv)
        else:
            self.blocks = -1  # make sure set_iv is called before encrypt

    def __cinit__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        self.ctx = EVP_CIPHER_CTX_new()

    def __dealloc__(self):
        EVP_CIPHER_CTX_free(self.ctx)

    cdef mac_compute(self, const unsigned char *data1, int data1_len,
                     const unsigned char *data2, int data2_len,
                     unsigned char *mac_buf):
        raise NotImplementedError

    cdef mac_verify(self, const unsigned char *data1, int data1_len,
                    const unsigned char *data2, int data2_len,
                    unsigned char *mac_buf, const unsigned char *mac_wanted):
        """
        Calculate MAC of *data1*, *data2*, write result to *mac_buf*, and verify against *mac_wanted.*
        """
        raise NotImplementedError

    def encrypt(self, data, header=b'', iv=None, aad=None):
        """
        encrypt data, compute mac over aad + iv + cdata, prepend header.
        aad_offset is the offset into the header where aad starts.
        """
        if iv is not None:
            self.set_iv(iv)
        assert self.blocks == 0, 'iv needs to be set before encrypt is called'
        cdef int ilen = len(data)
        cdef int hlen = len(header)
        assert hlen == self.header_len
        cdef int aoffset = self.aad_offset
        cdef int alen = hlen - aoffset
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef Py_buffer hdata
        cdef bint hdata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int olen
        cdef int offset

        try:
            odata = <unsigned char *>PyMem_Malloc(hlen + self.mac_len + self.iv_len_short +
                                                  ilen + self.cipher_blk_len)  # play safe, 1 extra blk
            if not odata:
                raise MemoryError

            idata = ro_buffer(data)
            idata_acquired = True
            hdata = ro_buffer(header)
            hdata_acquired = True

            offset = 0
            for i in range(hlen):
                odata[offset+i] = header[i]
            offset += hlen
            offset += self.mac_len
            self.store_iv(odata+offset, self.iv)
            offset += self.iv_len_short
            if not EVP_EncryptInit_ex(self.ctx, EVP_aes_256_ctr(), NULL, self.enc_key, self.iv):
                raise CryptoError('EVP_EncryptInit_ex failed')
            if not EVP_EncryptUpdate(self.ctx, odata+offset, &olen, <const unsigned char*> idata.buf, ilen):
                raise CryptoError('EVP_EncryptUpdate failed')
            offset += olen
            if not EVP_EncryptFinal_ex(self.ctx, odata+offset, &olen):
                raise CryptoError('EVP_EncryptFinal_ex failed')
            offset += olen
            self.mac_compute(<const unsigned char *> hdata.buf+aoffset, alen,
                              odata+hlen+self.mac_len, offset-hlen-self.mac_len,
                              odata+hlen)
            self.blocks += self.block_count(ilen)
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
            if hdata_acquired:
                PyBuffer_Release(&hdata)
            if idata_acquired:
                PyBuffer_Release(&idata)

    def decrypt(self, envelope, aad=None):
        """
        authenticate aad + iv + cdata, decrypt cdata, ignore header bytes up to aad_offset.
        """
        if len(envelope) < self.header_len + self.mac_len + self.iv_len_short:
            # truncated data - handle it like any other corruption or tampering, instead of
            # computing the MAC over negative lengths below.
            raise IntegrityError('MAC Authentication failed: envelope too short')
        cdef int ilen = len(envelope)
        cdef int hlen = self.header_len
        cdef int aoffset = self.aad_offset
        cdef int alen = hlen - aoffset
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int olen
        cdef int offset
        cdef int rc
        cdef unsigned char mac_buf[32]
        assert sizeof(mac_buf) == self.mac_len

        try:
            odata = <unsigned char *>PyMem_Malloc(ilen + self.cipher_blk_len)  # play safe, 1 extra blk
            if not odata:
                raise MemoryError

            idata = ro_buffer(envelope)
            idata_acquired = True

            self.mac_verify(<const unsigned char *> idata.buf+aoffset, alen,
                             <const unsigned char *> idata.buf+hlen+self.mac_len, ilen-hlen-self.mac_len,
                             mac_buf, <const unsigned char *> idata.buf+hlen)
            iv = self.fetch_iv(<unsigned char *> idata.buf+hlen+self.mac_len)
            self.set_iv(iv)
            if not EVP_DecryptInit_ex(self.ctx, EVP_aes_256_ctr(), NULL, self.enc_key, iv):
                raise CryptoError('EVP_DecryptInit_ex failed')
            offset = 0
            with nogil:
                rc = EVP_DecryptUpdate(self.ctx, odata+offset, &olen,
                                       <const unsigned char*> idata.buf+hlen+self.mac_len+self.iv_len_short,
                                       ilen-hlen-self.mac_len-self.iv_len_short)
            if not rc:
                raise CryptoError('EVP_DecryptUpdate failed')
            offset += olen
            if not EVP_DecryptFinal_ex(self.ctx, odata+offset, &olen):
                raise CryptoError('EVP_DecryptFinal_ex failed')
            offset += olen
            self.blocks += self.block_count(offset)
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
            if idata_acquired:
                PyBuffer_Release(&idata)

    def block_count(self, length):
        return num_cipher_blocks(length, self.cipher_blk_len)

    def set_iv(self, iv):
        # set_iv needs to be called before each encrypt() call
        if isinstance(iv, int):
            iv = iv.to_bytes(self.iv_len, byteorder='big')
        assert isinstance(iv, bytes) and len(iv) == self.iv_len
        self.iv = iv
        self.blocks = 0  # how many AES blocks got encrypted with this IV?

    def next_iv(self):
        # call this after encrypt() to get the next iv (int) for the next encrypt() call
        iv = int.from_bytes(self.iv[:self.iv_len], byteorder='big')
        return iv + self.blocks

    cdef fetch_iv(self, unsigned char * iv_in):
        # fetch lower self.iv_len_short bytes of iv and add upper zero bytes
        return b'\0' * (self.iv_len - self.iv_len_short) + iv_in[0:self.iv_len_short]

    cdef store_iv(self, unsigned char * iv_out, unsigned char * iv):
        # store only lower self.iv_len_short bytes, upper bytes are assumed to be 0
        cdef int i
        for i in range(self.iv_len_short):
            iv_out[i] = iv[(self.iv_len-self.iv_len_short)+i]

    def extract_iv(self, envelope):
        offset = self.header_len + self.mac_len
        return bytes_to_long(envelope[offset:offset+self.iv_len_short])


cdef class AES256_CTR_HMAC_SHA256(AES256_CTR_BASE):
    cdef unsigned char mac_key[32]

    def __init__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        assert isinstance(mac_key, bytes) and len(mac_key) == 32
        self.mac_key = mac_key
        super().__init__(mac_key, enc_key, iv=iv, header_len=header_len, aad_offset=aad_offset)

    def __cinit__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        pass

    def __dealloc__(self):
        pass

    cdef mac_compute(self, const unsigned char *data1, int data1_len,
                     const unsigned char *data2, int data2_len,
                     unsigned char *mac_buf):
        data = data1[:data1_len] + data2[:data2_len]
        mac = hmac.digest(self.mac_key[:self.mac_len], data, 'sha256')
        for i in range(self.mac_len):
            mac_buf[i] = mac[i]

    cdef mac_verify(self, const unsigned char *data1, int data1_len,
                    const unsigned char *data2, int data2_len,
                    unsigned char *mac_buf, const unsigned char *mac_wanted):
        self.mac_compute(data1, data1_len, data2, data2_len, mac_buf)
        if CRYPTO_memcmp(mac_buf, mac_wanted, self.mac_len):
            raise IntegrityError('MAC Authentication failed')


cdef class AES256_CTR_BLAKE2b(AES256_CTR_BASE):
    cdef unsigned char mac_key[128]

    def __init__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        assert isinstance(mac_key, bytes) and len(mac_key) == 128
        self.mac_key = mac_key
        super().__init__(mac_key, enc_key, iv=iv, header_len=header_len, aad_offset=aad_offset)

    def __cinit__(self, mac_key, enc_key, iv=None, header_len=1, aad_offset=1):
        pass

    def __dealloc__(self):
        pass

    cdef mac_compute(self, const unsigned char *data1, int data1_len,
                     const unsigned char *data2, int data2_len,
                     unsigned char *mac_buf):
        data = self.mac_key[:128] + data1[:data1_len] + data2[:data2_len]
        mac = hashlib.blake2b(data, digest_size=self.mac_len).digest()
        for i in range(self.mac_len):
            mac_buf[i] = mac[i]

    cdef mac_verify(self, const unsigned char *data1, int data1_len,
                    const unsigned char *data2, int data2_len,
                    unsigned char *mac_buf, const unsigned char *mac_wanted):
        self.mac_compute(data1, data1_len, data2, data2_len, mac_buf)
        if CRYPTO_memcmp(mac_buf, mac_wanted, self.mac_len):
            raise IntegrityError('MAC Authentication failed')


ctypedef const EVP_CIPHER * (* CIPHER)()


cdef class _AEAD_BASE:
    # new crypto used in borg >= 2.0
    # Layout: HEADER + MAC 16 + CT

    cdef CIPHER cipher
    cdef EVP_CIPHER_CTX *ctx
    cdef unsigned char key[32]
    cdef int cipher_blk_len
    cdef int iv_len
    cdef int aad_offset
    cdef int header_len_expected
    cdef int mac_len
    cdef unsigned char iv[12]
    cdef long long blocks

    @classmethod
    def requirements_check(cls):
        """check whether library requirements for this ciphersuite are satisfied"""
        raise NotImplementedError  # override / implement in child class

    def __init__(self, key, iv=None, header_len=0, aad_offset=0):
        """
        init AEAD crypto

        :param key: 256bit AEAD key
        :param iv: 96bit initialisation vector / nonce
        :param header_len: expected length of header
        :param aad_offset: where in the header the authenticated data starts
        """
        assert isinstance(key, bytes) and len(key) == 32
        self.iv_len = sizeof(self.iv)
        self.header_len_expected = header_len
        assert aad_offset <= header_len
        self.aad_offset = aad_offset
        self.mac_len = 16
        self.key = key
        if iv is not None:
            self.set_iv(iv)
        else:
            self.blocks = -1  # make sure set_iv is called before encrypt

    def __cinit__(self, key, iv=None, header_len=0, aad_offset=0):
        self.ctx = EVP_CIPHER_CTX_new()

    def __dealloc__(self):
        EVP_CIPHER_CTX_free(self.ctx)

    def encrypt(self, data, header=b'', iv=None, aad=b''):
        """
        encrypt data, compute auth tag over aad + header + cdata.
        return header + auth tag + cdata.
        aad_offset is the offset into the header where the authenticated header part starts.
        aad is additional authenticated data, which won't be included in the returned data,
        but only used for the auth tag computation.
        """
        if iv is not None:
            self.set_iv(iv)
        assert self.blocks == 0, 'iv needs to be set before encrypt is called'
        # CHACHA20 has an internal 32bit block counter (besides the 96bit (12Byte) IV we give it),
        # thus we must not encrypt more than 2^32 cipher blocks with the same (key, IV) pair.
        # AES-OCB has no such counter (it derives the per-block offsets from the IV), but we apply
        # the same limit to both ciphers: the check is cheap and can not trigger for borg messages
        # anyway, as these are limited to MAX_DATA_SIZE.
        block_count = self.block_count(len(data))
        if block_count > 2**32:
            raise ValueError('too much data for one message (max 2^32 cipher blocks)')
        cdef int ilen = len(data)
        cdef int hlen = len(header)
        assert hlen == self.header_len_expected
        cdef int aoffset = self.aad_offset
        cdef int alen = hlen - aoffset
        cdef int aadlen = len(aad)
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef Py_buffer hdata
        cdef bint hdata_acquired = False
        cdef Py_buffer aadata
        cdef bint aadata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int olen
        cdef int offset
        cdef int rc

        try:
            # Our AEAD ciphers (OCB, chacha20-poly1305) are padding-free: the ciphertext is
            # exactly as long as the plaintext. Thus the result can be allocated up front
            # and the cipher writes directly into it - no scratch buffer, no copy.
            ret = PyBytes_FromStringAndSize(NULL, hlen + self.mac_len + ilen)
            odata = <unsigned char *>PyBytes_AsString(ret)

            idata = ro_buffer(data)
            idata_acquired = True
            hdata = ro_buffer(header)
            hdata_acquired = True
            aadata = ro_buffer(aad)
            aadata_acquired = True
            offset = 0
            for i in range(hlen):
                odata[offset+i] = header[i]
            offset += hlen
            offset += self.mac_len
            if not EVP_EncryptInit_ex(self.ctx, self.cipher(), NULL, NULL, NULL):
                raise CryptoError('EVP_EncryptInit_ex failed')
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_SET_IVLEN, self.iv_len, NULL):
                raise CryptoError('EVP_CIPHER_CTX_ctrl SET IVLEN failed')
            if not EVP_EncryptInit_ex(self.ctx, NULL, NULL, self.key, self.iv):
                raise CryptoError('EVP_EncryptInit_ex failed')
            if not EVP_EncryptUpdate(self.ctx, NULL, &olen, <const unsigned char*> aadata.buf, aadlen):
                raise CryptoError('EVP_EncryptUpdate failed')
            if not EVP_EncryptUpdate(self.ctx, NULL, &olen, <const unsigned char*> hdata.buf+aoffset, alen):
                raise CryptoError('EVP_EncryptUpdate failed')
            with nogil:
                rc = EVP_EncryptUpdate(self.ctx, odata+offset, &olen, <const unsigned char*> idata.buf, ilen)
            if not rc:
                raise CryptoError('EVP_EncryptUpdate failed')
            offset += olen
            # Final can emit a buffered partial block (OCB does). Our AEAD modes are
            # padding-free, so it never writes more than the space left in the
            # exact-size result buffer.
            if not EVP_EncryptFinal_ex(self.ctx, odata+offset, &olen):
                raise CryptoError('EVP_EncryptFinal_ex failed')
            offset += olen
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_GET_TAG, self.mac_len, odata + hlen):
                raise CryptoError('EVP_CIPHER_CTX_ctrl GET TAG failed')
            if offset != hlen + self.mac_len + ilen:
                raise CryptoError('unexpected ciphertext length')
            self.blocks = block_count
            return ret
        finally:
            if hdata_acquired:
                PyBuffer_Release(&hdata)
            if idata_acquired:
                PyBuffer_Release(&idata)
            if aadata_acquired:
                PyBuffer_Release(&aadata)

    def decrypt(self, envelope, aad=b''):
        """
        authenticate aad + header + cdata (from envelope), ignore header bytes up to aad_offset,
        return decrypted cdata.
        """
        # same limit as for encryption, see there: we must not decrypt more than 2^32 cipher
        # blocks with the same (key, IV) pair.
        approx_block_count = self.block_count(len(envelope))  # sloppy, but good enough for borg
        if approx_block_count > 2**32:
            raise ValueError('too much data for one message (max 2^32 cipher blocks)')
        if len(envelope) < self.header_len_expected + self.mac_len:
            # truncated data - handle it like any other corruption or tampering, instead of
            # confusing OpenSSL with negative lengths below.
            raise IntegrityError('Authentication failed: envelope too short')
        cdef int ilen = len(envelope)
        cdef int hlen = self.header_len_expected
        cdef int aoffset = self.aad_offset
        cdef int alen = hlen - aoffset
        cdef int aadlen = len(aad)
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef Py_buffer aadata
        cdef bint aadata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int olen
        cdef int offset
        cdef int rc

        try:
            # Our AEAD ciphers (OCB, chacha20-poly1305) are padding-free: the plaintext is
            # exactly as long as the ciphertext. Thus the result can be allocated up front
            # and the cipher writes directly into it - no scratch buffer, no copy.
            ret = PyBytes_FromStringAndSize(NULL, ilen - hlen - self.mac_len)
            odata = <unsigned char *>PyBytes_AsString(ret)

            idata = ro_buffer(envelope)
            idata_acquired = True
            aadata = ro_buffer(aad)
            aadata_acquired = True
            if not EVP_DecryptInit_ex(self.ctx, self.cipher(), NULL, NULL, NULL):
                raise CryptoError('EVP_DecryptInit_ex failed')
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_SET_IVLEN, self.iv_len, NULL):
                raise CryptoError('EVP_CIPHER_CTX_ctrl SET IVLEN failed')
            if not EVP_DecryptInit_ex(self.ctx, NULL, NULL, self.key, self.iv):
                raise CryptoError('EVP_DecryptInit_ex failed')
            if not EVP_DecryptUpdate(self.ctx, NULL, &olen, <const unsigned char*> aadata.buf, aadlen):
                raise CryptoError('EVP_DecryptUpdate failed')
            if not EVP_DecryptUpdate(self.ctx, NULL, &olen, <const unsigned char*> idata.buf+aoffset, alen):
                raise CryptoError('EVP_DecryptUpdate failed')
            offset = 0
            with nogil:
                rc = EVP_DecryptUpdate(self.ctx, odata+offset, &olen,
                                       <const unsigned char*> idata.buf+hlen+self.mac_len,
                                       ilen-hlen-self.mac_len)
            if not rc:
                raise CryptoError('EVP_DecryptUpdate failed')
            offset += olen
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_SET_TAG, self.mac_len, <unsigned char *> idata.buf + hlen):
                raise CryptoError('EVP_CIPHER_CTX_ctrl SET TAG failed')
            # Final can emit a buffered partial block (OCB does). Our AEAD modes are
            # padding-free, so it never writes more than the space left in the
            # exact-size result buffer.
            if not EVP_DecryptFinal_ex(self.ctx, odata+offset, &olen):
                # a failure here means corrupted or tampered tag (mac) or data.
                raise IntegrityError('Authentication / EVP_DecryptFinal_ex failed')
            offset += olen
            if offset != ilen - hlen - self.mac_len:
                raise CryptoError('unexpected plaintext length')
            self.blocks = self.block_count(offset)
            return ret
        finally:
            if idata_acquired:
                PyBuffer_Release(&idata)
            if aadata_acquired:
                PyBuffer_Release(&aadata)

    def block_count(self, length):
        return num_cipher_blocks(length, self.cipher_blk_len)

    def set_iv(self, iv):
        # set_iv needs to be called before each encrypt() call,
        # because encrypt does a full initialisation of the cipher context.
        if isinstance(iv, int):
            iv = iv.to_bytes(self.iv_len, byteorder='big')
        assert isinstance(iv, bytes) and len(iv) == self.iv_len
        self.iv = iv
        self.blocks = 0  # number of cipher blocks encrypted with this IV

    def next_iv(self):
        # call this after encrypt() to get the next iv (int) for the next encrypt() call
        # the cipher blocks of a message do not consume IVs here (CHACHA20 counts them in its
        # internal 32bit block counter, AES-OCB derives the per-block offsets from the 96bit
        # (12 byte) IV we give it), thus we only need to increment the IV by 1 per message.
        iv = int.from_bytes(self.iv[:self.iv_len], byteorder='big')
        return iv + 1


cdef class AES256_OCB(_AEAD_BASE):
    @classmethod
    def requirements_check(cls):
        pass

    def __init__(self, key, iv=None, header_len=0, aad_offset=0):
        self.requirements_check()
        self.cipher = EVP_aes_256_ocb
        self.cipher_blk_len = 16
        super().__init__(key, iv=iv, header_len=header_len, aad_offset=aad_offset)


cdef class CHACHA20_POLY1305(_AEAD_BASE):
    @classmethod
    def requirements_check(cls):
        pass

    def __init__(self, key, iv=None, header_len=0, aad_offset=0):
        self.requirements_check()
        self.cipher = EVP_chacha20_poly1305
        self.cipher_blk_len = 64
        super().__init__(key, iv=iv, header_len=header_len, aad_offset=aad_offset)


def hmac_sha256(key, data):
    return hmac.digest(key, data, 'sha256')


def blake2b_256(key, data):
    return hashlib.blake2b(key+data, digest_size=32).digest()


def blake2b_128(data):
    return hashlib.blake2b(data, digest_size=16).digest()


cdef class CSPRNG:
    """
    Cryptographically Secure Pseudo-Random Number Generator based on AES-CTR mode.

    This class provides methods for generating random bytes and shuffling lists
    using a deterministic algorithm seeded with a 256-bit key.

    The implementation uses AES-256 in CTR mode, which is a well-established
    method for creating a CSPRNG.
    """
    cdef EVP_CIPHER_CTX *ctx
    cdef uint8_t key[32]
    cdef uint8_t iv[16]
    cdef uint8_t zeros[4096]  # Static buffer for zeros
    cdef uint8_t buffer[4096]  # Static buffer for random bytes
    cdef size_t buffer_size
    cdef size_t buffer_pos

    def __cinit__(self, bytes seed_key):
        """
        Initialize the CSPRNG with a 256-bit key.

        :param seed_key: A 32-byte key used as the seed for the CSPRNG
        """
        if len(seed_key) != 32:
            raise ValueError("Seed key must be 32 bytes (256 bits)")

        # Initialize context
        self.ctx = EVP_CIPHER_CTX_new()
        if self.ctx == NULL:
            raise MemoryError("Failed to allocate cipher context")

        self.key = seed_key[:32]

        # Initialize to zeros
        memset(self.iv, 0, 16)
        memset(self.zeros, 0, 4096)

        self.buffer_size = 4096
        self.buffer_pos = self.buffer_size  # Force refill on first use

        # Initialize the cipher
        if not EVP_EncryptInit_ex(self.ctx, EVP_aes_256_ctr(), NULL, self.key, self.iv):
            EVP_CIPHER_CTX_free(self.ctx)
            raise CryptoError("Failed to initialize AES-CTR cipher")

    def __dealloc__(self):
        """Free resources when the object is deallocated."""
        if self.ctx != NULL:
            EVP_CIPHER_CTX_free(self.ctx)
            self.ctx = NULL

    cdef _refill_buffer(self):
        """Refill the internal buffer with random bytes."""
        cdef int outlen = 0

        # Encrypt zeros to get random bytes
        if not EVP_EncryptUpdate(self.ctx, self.buffer, &outlen, self.zeros, self.buffer_size):
            raise CryptoError("Failed to generate random bytes")
        if outlen != self.buffer_size:
            raise CryptoError("Unexpected length of random bytes")

        self.buffer_pos = 0

    def random_bytes(self, size_t n):
        """
        Generate n random bytes.

        :param n: Number of bytes to generate
        :return: a bytes object containing the random bytes
        """
        # Directly create a Python bytes object of the required size
        cdef object py_bytes = PyBytes_FromStringAndSize(NULL, n)
        cdef uint8_t *result = <uint8_t *>PyBytes_AsString(py_bytes)
        cdef size_t remaining
        cdef size_t pos
        cdef size_t to_copy
        cdef size_t available

        remaining = n
        pos = 0

        while remaining > 0:
            if self.buffer_pos >= self.buffer_size:
                self._refill_buffer()

            # Calculate how many bytes we can copy
            available = self.buffer_size - self.buffer_pos
            to_copy = remaining if remaining < available else available

            # Copy bytes from buffer to result
            memcpy(result + pos, &self.buffer[self.buffer_pos], to_copy)

            self.buffer_pos += to_copy
            pos += to_copy
            remaining -= to_copy

        return py_bytes

    def random_int(self, n):
        """
        Generate a random integer in the range [0, n).

        :param n: Upper bound (exclusive)
        :return: Random integer
        """
        if n <= 0:
            raise ValueError("Upper bound must be positive")
        if n == 1:
            return 0

        # Calculate the number of bits and bytes needed
        bits_needed = 0
        temp = n - 1
        while temp > 0:
            bits_needed += 1
            temp >>= 1
        bytes_needed = (bits_needed + 7) // 8

        # Generate random bytes
        mask = (1 << bits_needed) - 1
        max_attempts = 1000  # Prevent infinite loop

        # Rejection sampling to avoid bias
        attempts = 0
        while attempts < max_attempts:
            attempts += 1
            random_data = self.random_bytes(bytes_needed)
            result = int.from_bytes(random_data, byteorder='big')

            # Apply mask to get the right number of bits
            result &= mask
            if result < n:
                return result

        # If we reach here, we've made too many attempts
        # Fall back to a slightly biased but guaranteed-to-terminate method
        random_data = self.random_bytes(bytes_needed)
        result = int.from_bytes(random_data, byteorder='big')
        return result % n

    def shuffle(self, list items):
        """
        Shuffle a list in-place using the Fisher-Yates algorithm.

        :param items: List to shuffle
        """
        cdef size_t n = len(items)
        cdef size_t i, j

        for i in range(n - 1, 0, -1):
            # Generate random index j such that 0 <= j <= i
            j = self.random_int(i + 1)

            # Swap items[i] and items[j]
            items[i], items[j] = items[j], items[i]


# XXH64: a pure-cython, dependency-free implementation of the (non-cryptographic) xxHash-64 hash.
#
# This only exists to support `borg transfer` from borg 1.x repos, see #9935:
# borg 1.x stored XXH64 checksums in the repository's index/hints integrity data, so we need
# XXH64 to verify those files when opening a borg 1.x (legacy) repository. It is not used for
# anything in borg 2.x native repos and MUST NOT be used as a security mechanism.
#
# Reference: https://github.com/Cyan4973/xxHash (algorithm is in the public domain / BSD-2-Clause).
# The digest uses the canonical (big-endian) representation, matching what borg 1.x wrote
# (it used the "xxhash" PyPI package, whose digest()/hexdigest() are big-endian).

cdef extern from *:
    """
    #include <stdint.h>
    /* xxHash-64 prime constants, defined as real uint64_t so there is no ambiguity
       about the width/signedness of these (large) literals. */
    static const uint64_t BORG_XXH64_P1 = 0x9E3779B185EBCA87ULL;
    static const uint64_t BORG_XXH64_P2 = 0xC2B2AE3D27D4EB4FULL;
    static const uint64_t BORG_XXH64_P3 = 0x165667B19E3779F9ULL;
    static const uint64_t BORG_XXH64_P4 = 0x85EBCA77C2B2AE63ULL;
    static const uint64_t BORG_XXH64_P5 = 0x27D4EB2F165667C5ULL;
    """
    const uint64_t BORG_XXH64_P1
    const uint64_t BORG_XXH64_P2
    const uint64_t BORG_XXH64_P3
    const uint64_t BORG_XXH64_P4
    const uint64_t BORG_XXH64_P5


cdef inline uint64_t _xxh_rotl(uint64_t x, int r) noexcept nogil:
    return (x << r) | (x >> (64 - r))


cdef inline uint64_t _xxh_round(uint64_t acc, uint64_t inp) noexcept nogil:
    acc += inp * BORG_XXH64_P2
    acc = _xxh_rotl(acc, 31)
    acc *= BORG_XXH64_P1
    return acc


cdef inline uint64_t _xxh_merge(uint64_t acc, uint64_t val) noexcept nogil:
    acc ^= _xxh_round(0, val)
    acc = acc * BORG_XXH64_P1 + BORG_XXH64_P4
    return acc


# read 64/32 bits little-endian, byte-wise, so this is correct on both little- and big-endian hosts.
cdef inline uint64_t _xxh_read64(const uint8_t *p) noexcept nogil:
    return (<uint64_t>p[0] | (<uint64_t>p[1] << 8) | (<uint64_t>p[2] << 16) | (<uint64_t>p[3] << 24) |
            (<uint64_t>p[4] << 32) | (<uint64_t>p[5] << 40) | (<uint64_t>p[6] << 48) | (<uint64_t>p[7] << 56))


cdef inline uint32_t _xxh_read32(const uint8_t *p) noexcept nogil:
    return (<uint32_t>p[0] | (<uint32_t>p[1] << 8) | (<uint32_t>p[2] << 16) | (<uint32_t>p[3] << 24))


cdef class XXH64:
    """
    Streaming XXH64 hasher with an interface compatible with the "xxhash" PyPI package's xxh64
    (as used by borg 1.x): XXH64([data], [seed]) then .update(data) and .digest()/.hexdigest().

    See the comment above: this exists only to support `borg transfer` from borg 1.x repos, #9935.
    """
    cdef uint64_t v1, v2, v3, v4
    cdef uint64_t total_len
    cdef uint64_t seed
    cdef uint8_t mem[32]
    cdef unsigned int memsize

    def __init__(self, data=b"", seed=0):
        # coerce seed into a C uint64_t first, so the setup arithmetic below wraps in C
        # (mod 2**64) instead of overflowing as an unbounded python int.
        cdef uint64_t s = seed
        self.seed = s
        self.v1 = s + BORG_XXH64_P1 + BORG_XXH64_P2
        self.v2 = s + BORG_XXH64_P2
        self.v3 = s
        self.v4 = s - BORG_XXH64_P1
        self.total_len = 0
        self.memsize = 0
        if data:
            self.update(data)

    def update(self, data):
        cdef Py_buffer view
        PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
        try:
            with nogil:
                self._update(<const uint8_t *> view.buf, view.len)
        finally:
            PyBuffer_Release(&view)

    cdef void _update(self, const uint8_t *p, Py_ssize_t length) noexcept nogil:
        cdef const uint8_t *end = p + length
        cdef const uint8_t *limit
        cdef unsigned int fill
        self.total_len += length
        if self.memsize + length < 32:
            # not enough (even together with buffered data) for a full 32-byte stripe: just buffer it.
            memcpy(&self.mem[self.memsize], p, length)
            self.memsize += <unsigned int> length
            return
        if self.memsize > 0:
            # complete and process the buffered partial stripe first.
            fill = 32 - self.memsize
            memcpy(&self.mem[self.memsize], p, fill)
            self.v1 = _xxh_round(self.v1, _xxh_read64(&self.mem[0]))
            self.v2 = _xxh_round(self.v2, _xxh_read64(&self.mem[8]))
            self.v3 = _xxh_round(self.v3, _xxh_read64(&self.mem[16]))
            self.v4 = _xxh_round(self.v4, _xxh_read64(&self.mem[24]))
            p += fill
            self.memsize = 0
        # process full 32-byte stripes directly from the input.
        limit = end - 32
        while p <= limit:
            self.v1 = _xxh_round(self.v1, _xxh_read64(p)); p += 8
            self.v2 = _xxh_round(self.v2, _xxh_read64(p)); p += 8
            self.v3 = _xxh_round(self.v3, _xxh_read64(p)); p += 8
            self.v4 = _xxh_round(self.v4, _xxh_read64(p)); p += 8
        # buffer the remaining (< 32) bytes for the next update()/digest().
        if p < end:
            memcpy(&self.mem[0], p, end - p)
            self.memsize = <unsigned int> (end - p)

    def digest(self):
        """Return the digest as 8 bytes, in canonical (big-endian) representation."""
        cdef uint64_t h
        cdef const uint8_t *p = &self.mem[0]
        cdef const uint8_t *end = &self.mem[self.memsize]
        cdef uint8_t out[8]
        cdef int i
        if self.total_len >= 32:
            h = _xxh_rotl(self.v1, 1) + _xxh_rotl(self.v2, 7) + _xxh_rotl(self.v3, 12) + _xxh_rotl(self.v4, 18)
            h = _xxh_merge(h, self.v1)
            h = _xxh_merge(h, self.v2)
            h = _xxh_merge(h, self.v3)
            h = _xxh_merge(h, self.v4)
        else:
            h = self.seed + BORG_XXH64_P5
        h += self.total_len
        while p + 8 <= end:
            h ^= _xxh_round(0, _xxh_read64(p))
            h = _xxh_rotl(h, 27) * BORG_XXH64_P1 + BORG_XXH64_P4
            p += 8
        if p + 4 <= end:
            h ^= <uint64_t> _xxh_read32(p) * BORG_XXH64_P1
            h = _xxh_rotl(h, 23) * BORG_XXH64_P2 + BORG_XXH64_P3
            p += 4
        while p < end:
            h ^= <uint64_t> p[0] * BORG_XXH64_P5
            h = _xxh_rotl(h, 11) * BORG_XXH64_P1
            p += 1
        # final avalanche
        h ^= h >> 33
        h *= BORG_XXH64_P2
        h ^= h >> 29
        h *= BORG_XXH64_P3
        h ^= h >> 32
        for i in range(8):
            out[i] = <uint8_t> (h >> (56 - 8 * i))  # big-endian
        return PyBytes_FromStringAndSize(<char *> out, 8)

    def hexdigest(self):
        """Return the digest as a 16-character hex string (canonical, big-endian)."""
        return self.digest().hex()


def xxh64(data, seed=0):
    """One-shot XXH64: return the 8-byte canonical (big-endian) digest of *data*."""
    return XXH64(data, seed).digest()
