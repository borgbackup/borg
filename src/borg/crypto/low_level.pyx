"""An AEAD-style OpenSSL wrapper

API:

    encrypt(data, header=b'', aad_offset=0) -> envelope
    decrypt(envelope, header_len=0, aad_offset=0) -> data

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

IV handling:

    iv = ...  # just never repeat!
    cs = CS(hmac_key, enc_key, iv=iv)
    envelope = cs.encrypt(data, header, aad_offset)
    iv = cs.next_iv(len(data))
    (repeat)
"""

import hashlib
import hmac
from math import ceil

from cpython cimport PyMem_Malloc, PyMem_Free
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_AsString
from libc.stdlib cimport malloc, free
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.string cimport memset, memcpy



cdef extern from "openssl/crypto.h":
    int CRYPTO_memcmp(const void *a, const void *b, size_t len)

cdef extern from "openssl/opensslv.h":
    long OPENSSL_VERSION_NUMBER

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
    const EVP_CIPHER *EVP_aes_256_ocb()
    const EVP_CIPHER *EVP_chacha20_poly1305()

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new()
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a)
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

    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
    int EVP_CTRL_AEAD_GET_TAG
    int EVP_CTRL_AEAD_SET_TAG
    int EVP_CTRL_AEAD_SET_IVLEN


cdef extern from "openssl/evp.h":
    # asymmetric keys (Ed25519 signing, X25519 key agreement for HPKE)
    ctypedef struct EVP_PKEY:
        pass
    ctypedef struct EVP_PKEY_CTX:
        pass
    ctypedef struct EVP_MD_CTX:
        pass

    int EVP_PKEY_ED25519
    int EVP_PKEY_X25519

    EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e, const unsigned char *key, size_t keylen)
    EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e, const unsigned char *key, size_t keylen)
    int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub, size_t *len)
    void EVP_PKEY_free(EVP_PKEY *key)

    EVP_MD_CTX *EVP_MD_CTX_new()
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
    int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
    int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
    int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
    int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen)


cdef extern from "openssl/hpke.h":
    ctypedef struct OSSL_HPKE_SUITE:
        uint16_t kem_id
        uint16_t kdf_id
        uint16_t aead_id
    ctypedef struct OSSL_HPKE_CTX:
        pass
    ctypedef struct OSSL_LIB_CTX:
        pass

    int OSSL_HPKE_MODE_BASE
    int OSSL_HPKE_ROLE_SENDER
    int OSSL_HPKE_ROLE_RECEIVER
    uint16_t OSSL_HPKE_KEM_ID_X25519
    uint16_t OSSL_HPKE_KDF_ID_HKDF_SHA256
    uint16_t OSSL_HPKE_AEAD_ID_AES_GCM_256

    OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite, int role,
                                     OSSL_LIB_CTX *libctx, const char *propq)
    void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx)
    int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx, unsigned char *enc, size_t *enclen,
                        const unsigned char *pub, size_t publen,
                        const unsigned char *info, size_t infolen)
    int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx, unsigned char *ct, size_t *ctlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *pt, size_t ptlen)
    int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx, const unsigned char *enc, size_t enclen,
                        EVP_PKEY *recippriv, const unsigned char *info, size_t infolen)
    int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx, unsigned char *pt, size_t *ptlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *ct, size_t ctlen)
    size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite)
    size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen)


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
        cdef int ilen = len(envelope)
        cdef int hlen = self.header_len
        cdef int aoffset = self.aad_offset
        cdef int alen = hlen - aoffset
        cdef Py_buffer idata
        cdef bint idata_acquired = False
        cdef unsigned char *odata = NULL
        cdef int olen
        cdef int offset
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
            if not EVP_DecryptUpdate(self.ctx, odata+offset, &olen,
                                     <const unsigned char*> idata.buf+hlen+self.mac_len+self.iv_len_short,
                                     ilen-hlen-self.mac_len-self.iv_len_short):
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
        raise NotImplemented  # override / implement in child class

    def __init__(self, key, iv=None, header_len=0, aad_offset=0):
        """
        init AEAD crypto

        :param key: 256bit encrypt-then-mac key
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
        # AES-OCB, CHACHA20 ciphers all add a internal 32bit counter to the 96bit (12Byte)
        # IV we provide, thus we must not encrypt more than 2^32 cipher blocks with same IV).
        block_count = self.block_count(len(data))
        if block_count > 2**32:
            raise ValueError('too much data, would overflow internal 32bit counter')
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

        try:
            odata = <unsigned char *>PyMem_Malloc(hlen + self.mac_len +
                                                  ilen + self.cipher_blk_len)
            if not odata:
                raise MemoryError

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
            if not EVP_EncryptUpdate(self.ctx, odata+offset, &olen, <const unsigned char*> idata.buf, ilen):
                raise CryptoError('EVP_EncryptUpdate failed')
            offset += olen
            if not EVP_EncryptFinal_ex(self.ctx, odata+offset, &olen):
                raise CryptoError('EVP_EncryptFinal_ex failed')
            offset += olen
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_GET_TAG, self.mac_len, odata + hlen):
                raise CryptoError('EVP_CIPHER_CTX_ctrl GET TAG failed')
            self.blocks = block_count
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
            if hdata_acquired:
                PyBuffer_Release(&hdata)
            if idata_acquired:
                PyBuffer_Release(&idata)
            if aadata_acquired:
                PyBuffer_Release(&aadata)

    def decrypt(self, envelope, aad=b''):
        """
        authenticate aad + header + cdata (from envelope), ignore header bytes up to aad_offset.,
        return decrypted cdata.
        """
        # AES-OCB, CHACHA20 ciphers all add a internal 32bit counter to the 96bit (12Byte)
        # IV we provide, thus we must not decrypt more than 2^32 cipher blocks with same IV):
        approx_block_count = self.block_count(len(envelope))  # sloppy, but good enough for borg
        if approx_block_count > 2**32:
            raise ValueError('too much data, would overflow internal 32bit counter')
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

        try:
            odata = <unsigned char *>PyMem_Malloc(ilen + self.cipher_blk_len)
            if not odata:
                raise MemoryError

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
            if not EVP_DecryptUpdate(self.ctx, odata+offset, &olen,
                                     <const unsigned char*> idata.buf+hlen+self.mac_len,
                                     ilen-hlen-self.mac_len):
                raise CryptoError('EVP_DecryptUpdate failed')
            offset += olen
            if not EVP_CIPHER_CTX_ctrl(self.ctx, EVP_CTRL_AEAD_SET_TAG, self.mac_len, <unsigned char *> idata.buf + hlen):
                raise CryptoError('EVP_CIPHER_CTX_ctrl SET TAG failed')
            if not EVP_DecryptFinal_ex(self.ctx, odata+offset, &olen):
                # a failure here means corrupted or tampered tag (mac) or data.
                raise IntegrityError('Authentication / EVP_DecryptFinal_ex failed')
            offset += olen
            self.blocks = self.block_count(offset)
            return odata[:offset]
        finally:
            if odata:
                PyMem_Free(odata)
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
        # AES-OCB, CHACHA20 ciphers all add a internal 32bit counter to the 96bit
        # (12 byte) IV we provide, thus we only need to increment the IV by 1.
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


# Asymmetric primitives used for monitoring reports: Ed25519 signatures (authenticity)
# and HPKE (RFC 9180) sealing (confidentiality from the untrusted repo server). Both are
# provided by OpenSSL >= 3.2; key material is 32-byte seeds derived from the borg key.

ED25519_SEED_SIZE = 32
ED25519_PUBLIC_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
X25519_SEED_SIZE = 32
X25519_PUBLIC_SIZE = 32


cdef OSSL_HPKE_SUITE _hpke_suite():
    # DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
    cdef OSSL_HPKE_SUITE suite
    suite.kem_id = OSSL_HPKE_KEM_ID_X25519
    suite.kdf_id = OSSL_HPKE_KDF_ID_HKDF_SHA256
    suite.aead_id = OSSL_HPKE_AEAD_ID_AES_GCM_256
    return suite


cdef bytes _raw_public_key(int pkey_type, bytes seed):
    if len(seed) != 32:
        raise ValueError("raw key seed must be 32 bytes")
    cdef EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(pkey_type, NULL, <const unsigned char *> PyBytes_AsString(seed), 32)
    if pkey == NULL:
        raise CryptoError("EVP_PKEY_new_raw_private_key failed")
    cdef unsigned char pub[32]
    cdef size_t publen = 32
    try:
        if not EVP_PKEY_get_raw_public_key(pkey, pub, &publen):
            raise CryptoError("EVP_PKEY_get_raw_public_key failed")
        return PyBytes_FromStringAndSize(<char *> pub, publen)
    finally:
        EVP_PKEY_free(pkey)


def ed25519_public_from_seed(bytes seed):
    """Return the 32-byte Ed25519 public key for a 32-byte secret seed."""
    return _raw_public_key(EVP_PKEY_ED25519, seed)


def x25519_public_from_seed(bytes seed):
    """Return the 32-byte X25519 (HPKE) public key for a 32-byte secret seed."""
    return _raw_public_key(EVP_PKEY_X25519, seed)


def ed25519_sign(bytes seed, bytes data):
    """Sign *data* with the Ed25519 secret *seed* (32 bytes), returning a 64-byte signature."""
    if len(seed) != ED25519_SEED_SIZE:
        raise ValueError("ed25519 seed must be 32 bytes")
    cdef EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, <const unsigned char *> PyBytes_AsString(seed), 32)
    if pkey == NULL:
        raise CryptoError("EVP_PKEY_new_raw_private_key(ED25519) failed")
    cdef EVP_MD_CTX *mdctx = EVP_MD_CTX_new()
    cdef unsigned char sig[64]
    cdef size_t siglen = 64
    try:
        if mdctx == NULL:
            raise CryptoError("EVP_MD_CTX_new failed")
        if not EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey):
            raise CryptoError("EVP_DigestSignInit failed")
        if not EVP_DigestSign(mdctx, sig, &siglen, <const unsigned char *> PyBytes_AsString(data), len(data)):
            raise CryptoError("EVP_DigestSign failed")
        return PyBytes_FromStringAndSize(<char *> sig, siglen)
    finally:
        if mdctx != NULL:
            EVP_MD_CTX_free(mdctx)
        EVP_PKEY_free(pkey)


def ed25519_verify(bytes public, bytes data, bytes signature):
    """Verify an Ed25519 *signature* over *data* with the 32-byte *public* key.

    Returns None on success, raises IntegrityError on a bad signature.
    """
    if len(public) != ED25519_PUBLIC_SIZE:
        raise ValueError("ed25519 public key must be 32 bytes")
    cdef EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, <const unsigned char *> PyBytes_AsString(public), 32)
    if pkey == NULL:
        raise CryptoError("EVP_PKEY_new_raw_public_key(ED25519) failed")
    cdef EVP_MD_CTX *mdctx = EVP_MD_CTX_new()
    cdef int rc
    try:
        if mdctx == NULL:
            raise CryptoError("EVP_MD_CTX_new failed")
        if not EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey):
            raise CryptoError("EVP_DigestVerifyInit failed")
        rc = EVP_DigestVerify(mdctx, <const unsigned char *> PyBytes_AsString(signature), len(signature),
                              <const unsigned char *> PyBytes_AsString(data), len(data))
        if rc != 1:
            raise IntegrityError("Ed25519 signature verification failed")
    finally:
        if mdctx != NULL:
            EVP_MD_CTX_free(mdctx)
        EVP_PKEY_free(pkey)


def hpke_seal(bytes recipient_public, bytes info, bytes aad, bytes plaintext):
    """HPKE-seal *plaintext* to the recipient's 32-byte X25519 *public* key.

    Returns enc || ciphertext (the encapsulated key prepended to the AEAD ciphertext).
    """
    if len(recipient_public) != X25519_PUBLIC_SIZE:
        raise ValueError("recipient public key must be 32 bytes")
    cdef OSSL_HPKE_SUITE suite = _hpke_suite()
    cdef OSSL_HPKE_CTX *ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL)
    cdef size_t enclen = OSSL_HPKE_get_public_encap_size(suite)
    cdef size_t ctlen = OSSL_HPKE_get_ciphertext_size(suite, len(plaintext))
    cdef unsigned char *enc = <unsigned char *> malloc(enclen)
    cdef unsigned char *ct = <unsigned char *> malloc(ctlen)
    try:
        if ctx == NULL or enc == NULL or ct == NULL:
            raise CryptoError("HPKE sender setup failed")
        if not OSSL_HPKE_encap(ctx, enc, &enclen,
                               <const unsigned char *> PyBytes_AsString(recipient_public), 32,
                               <const unsigned char *> PyBytes_AsString(info), len(info)):
            raise CryptoError("OSSL_HPKE_encap failed")
        if not OSSL_HPKE_seal(ctx, ct, &ctlen,
                              <const unsigned char *> PyBytes_AsString(aad), len(aad),
                              <const unsigned char *> PyBytes_AsString(plaintext), len(plaintext)):
            raise CryptoError("OSSL_HPKE_seal failed")
        return PyBytes_FromStringAndSize(<char *> enc, enclen) + PyBytes_FromStringAndSize(<char *> ct, ctlen)
    finally:
        if enc != NULL:
            free(enc)
        if ct != NULL:
            free(ct)
        if ctx != NULL:
            OSSL_HPKE_CTX_free(ctx)


def hpke_open(bytes recipient_secret, bytes info, bytes aad, bytes blob):
    """HPKE-open a *blob* (enc || ciphertext) with the recipient's 32-byte X25519 secret.

    Returns the plaintext, raises IntegrityError if opening/authentication fails.
    """
    if len(recipient_secret) != X25519_SEED_SIZE:
        raise ValueError("recipient secret key must be 32 bytes")
    cdef OSSL_HPKE_SUITE suite = _hpke_suite()
    cdef size_t enclen = OSSL_HPKE_get_public_encap_size(suite)
    if len(blob) < enclen:
        raise IntegrityError("HPKE blob too short")
    cdef bytes enc = blob[:enclen]
    cdef bytes ct = blob[enclen:]
    cdef EVP_PKEY *recippriv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, <const unsigned char *> PyBytes_AsString(recipient_secret), 32)
    cdef OSSL_HPKE_CTX *ctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL)
    cdef size_t ptlen = len(ct) + 1
    cdef unsigned char *pt = <unsigned char *> malloc(ptlen)
    try:
        if recippriv == NULL or ctx == NULL or pt == NULL:
            raise CryptoError("HPKE receiver setup failed")
        if not OSSL_HPKE_decap(ctx, <const unsigned char *> PyBytes_AsString(enc), len(enc),
                               recippriv, <const unsigned char *> PyBytes_AsString(info), len(info)):
            raise IntegrityError("OSSL_HPKE_decap failed")
        if not OSSL_HPKE_open(ctx, pt, &ptlen,
                              <const unsigned char *> PyBytes_AsString(aad), len(aad),
                              <const unsigned char *> PyBytes_AsString(ct), len(ct)):
            raise IntegrityError("OSSL_HPKE_open failed")
        return PyBytes_FromStringAndSize(<char *> pt, ptlen)
    finally:
        if pt != NULL:
            free(pt)
        if ctx != NULL:
            OSSL_HPKE_CTX_free(ctx)
        if recippriv != NULL:
            EVP_PKEY_free(recippriv)


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
