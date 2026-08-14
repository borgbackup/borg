# cython: language_level=3

import os
import cython

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.string cimport memset

from .phte_chunker cimport ChunkerPHTE

from ..crypto.low_level import CSPRNG


# goldilocks-aes: the reference "Chk-PHTE" construction of eprint 2025/558
# ("Breaking and Fixing Content-Defined Chunking"; Truong, Merz, Scarlata,
# Guenther, Paterson), implemented borg-style for comparison with rabin-aes.
#
# Same UHF-then-PRF split as rabin-aes (see rabin_aes.pyx for the full
# motivation); only the UHF differs:
#
#   1. the rolling *universal hash* is a polynomial hash over the prime field
#      GF(p) with p = 2^64 - 2^32 + 1 (the "Goldilocks" prime, chosen for its
#      cheap 2^64 = 2^32 - 1 reduction) at a secret random evaluation point K:
#      over the 64-byte window, state = sum b_j * K^(63-j) mod p (oldest byte
#      at K^63, newest at K^0). This is the UHF the paper's own reference
#      implementation uses (their Rust prf-chunker, via the risc0 Goldilocks
#      field). Two distinct windows collide with probability <= 63/p ~= 2^-58
#      over the choice of K (the difference is a nonzero polynomial in K of
#      degree <= 63) - a slightly *better* bound than rabin-aes's <= 511/2^63,
#      because the polynomial is over bytes, not bits.
#   2. a *PRF* (AES-128 with a secret key) is applied to the state; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(state) & mask) == 0.
#
# The kernel keeps all field values canonical (< p), so the AES input is a
# unique function of the window and all code paths cut identically.
#
# Performance: same batching structure as rabin-aes (the state stream is
# independent of where cuts happen), same two-lane rolling and grouped AES;
# the difference under test is purely GF(p) multiply-based rolling versus
# GF(2)[x] table-based rolling.

cdef extern from "goldilocks_aes_impl.h":
    ctypedef struct GL_CTX:
        pass
    int GL_TABLES
    GL_CTX *gl_new(const uint64_t *tables, uint64_t k1, uint64_t k2, const uint8_t *aes_key, int kernel)
    int phte_kernel_select(const char *name, int *out_id)
    const char *phte_kernel_names()
    int PHTE_K_EVP
    int PHTE_K_HW
    void gl_free(GL_CTX *ctx)
    const char *gl_kind(const GL_CTX *ctx)
    uint64_t gl_digest64(const GL_CTX *ctx, const uint8_t *q)
    int64_t gl_scan(GL_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) nogil


# --- Goldilocks field helpers (pure Python, used at chunker setup only) ---

_GL_P = 0xFFFFFFFF00000001  # the Goldilocks prime 2^64 - 2^32 + 1
_WINDOW_SIZE = 64  # bytes


def _sample_key_elem(rng):
    """Sample the secret evaluation point K uniformly from GF(p) (rejection).

    Uniformity over the whole field is exactly what the collision bound needs;
    a candidate is rejected with probability ~2^-32, so this almost always
    accepts the first sample.
    """
    while True:
        v = int.from_bytes(rng.random_bytes(8), "little")
        if v < _GL_P:
            return v


def _build_tables(k):
    """Build the rolling tables for K (order must match GL_TABLES in the C kernel).

    nout64_tbl[b] = (-b * K^64) mod p  (removal of the byte leaving the window)
    nout65_tbl[b] = (-b * K^65) mod p  (stride-2 removal, older leaving byte)
    in1_tbl[b]    = ( b * K   ) mod p  (stride-2, older incoming byte)

    The removal tables are negated so the C kernel's per-byte delta is a pure
    sum; the stride-2 tables are algebraic combinations of the single-step
    update and let the kernel run two independent even/odd rolling lanes (see
    goldilocks_aes_impl.c) without changing any cut point.
    """
    k64 = pow(k, _WINDOW_SIZE, _GL_P)
    k65 = (k64 * k) % _GL_P
    nout64_tbl = [(-b * k64) % _GL_P for b in range(256)]
    nout65_tbl = [(-b * k65) % _GL_P for b in range(256)]
    in1_tbl = [(b * k) % _GL_P for b in range(256)]
    return nout64_tbl, nout65_tbl, in1_tbl


def _derive(bytes key):
    """Derive (aes_key, K, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then K
    (8 bytes per candidate until accepted).
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    k = _sample_key_elem(rng)
    tables = _build_tables(k)
    return aes_key, k, tables


from .kernel_env import kernel_error, requested_kernel


cdef int _select_kernel() except -1:
    """Resolve BORG_AES_CHUNKER_KERNEL to a scan path id, raising if it cannot be honoured.

    One selector for all three AES chunkers: they share phte_scan.h, so the
    available paths never differ between them.
    """
    cdef int kid = PHTE_K_EVP
    cdef int rc
    want = requested_kernel("BORG_AES_CHUNKER_KERNEL")
    if want is None:
        return PHTE_K_EVP
    rc = phte_kernel_select(want.encode("ascii"), &kid)
    if rc != 0:
        raise kernel_error("BORG_AES_CHUNKER_KERNEL", want, rc,
                           (<bytes>phte_kernel_names()).decode("ascii"))
    return kid


cdef class ChunkerGoldilocksAES(ChunkerPHTE):
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling polynomial hash over the Goldilocks prime field (secret evaluation
    point, 64-byte window) post-processed with AES-128; the cut decision only
    sees the AES output, so observed chunk boundaries do not leak usable
    information about the chunking secret (see module docstring).
    """
    cdef GL_CTX* ctx

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int nc_level=0, size_t normal_size=0, bint sparse=False):
        cdef uint64_t c_tables[3 * 256]
        cdef int i, t
        self.ctx = NULL
        self._setup("goldilocks-aes", chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level, normal_size, sparse)

        aes_key, k, tables = _derive(key)
        assert len(tables) == GL_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]

        kernel = _select_kernel()
        self.ctx = gl_new(c_tables, k, (k * k) % _GL_P, aes_key, kernel)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up goldilocks-aes kernel")
        self.kernel_str = (<bytes>gl_kind(self.ctx)).decode("ascii")

    def __dealloc__(self):
        if self.ctx != NULL:
            gl_free(self.ctx)
            self.ctx = NULL

    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept:
        cdef int64_t r
        with nogil:
            r = gl_scan(self.ctx, p, n, digest, mask)
        return r

    cdef uint64_t _digest64(self, const uint8_t *q) noexcept:
        return gl_digest64(self.ctx, q)


def goldilocks_aes_get_key_elem(bytes key):
    """Get the secret evaluation point K derived from <key> (for tests)."""
    aes_key, k, tables = _derive(key)
    return k


def goldilocks_aes_get_tables(bytes key):
    """Get the (nout64, nout65, in1) rolling tables derived from <key> (for tests)."""
    aes_key, k, tables = _derive(key)
    return tables


def goldilocks_aes_digest64(k, bytes window):
    """C-kernel Horner digest of a 64-byte window for evaluation point k (for tests).

    Lets tests verify the kernel's GF(p) arithmetic (gl_mul/gl_add) against a
    pure-Python big-int reference, including values close to p.
    """
    cdef uint64_t c_tables[3 * 256]
    cdef uint8_t aes_key[16]
    cdef GL_CTX *ctx
    cdef uint64_t d
    cdef int i, t
    assert len(window) == _WINDOW_SIZE
    assert 0 <= k < _GL_P
    tables = _build_tables(k)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    memset(aes_key, 0, 16)
    ctx = gl_new(c_tables, k, (k * k) % _GL_P, aes_key, PHTE_K_EVP)
    if ctx == NULL:
        raise MemoryError("Failed to set up goldilocks-aes kernel")
    d = gl_digest64(ctx, <const uint8_t*>PyBytes_AsString(window))
    gl_free(ctx)
    return d


def goldilocks_aes_scan_all(k, bytes aes_key, bytes data, mask, bint force_sw=False):
    """Raw kernel scan over all window positions >= 64 (for tests).

    Returns the list of positions i where the cut condition matches, i.e.
    (AES(state of window data[i-63..i]) & mask) == 0 - independent of any
    chunk min/max framing. force_sw selects the portable EVP path, otherwise
    the AES hardware path is used (which falls back to EVP where the CPU has
    no AES instructions).
    """
    cdef uint64_t c_tables[3 * 256]
    cdef GL_CTX *ctx
    cdef const uint8_t *base
    cdef uint64_t digest, c_mask = mask
    cdef size_t pos, n
    cdef int64_t r
    cdef int i, t
    assert 0 <= k < _GL_P
    assert len(aes_key) == 16
    assert len(data) > _WINDOW_SIZE
    tables = _build_tables(k)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    ctx = gl_new(c_tables, k, (k * k) % _GL_P, <const uint8_t*>PyBytes_AsString(aes_key), PHTE_K_EVP if force_sw else PHTE_K_HW)
    if ctx == NULL:
        raise MemoryError("Failed to set up goldilocks-aes kernel")
    try:
        base = <const uint8_t*>PyBytes_AsString(data)
        n = len(data)
        digest = gl_digest64(ctx, base)  # state at position 63
        pos = _WINDOW_SIZE
        result = []
        while pos < n:
            r = gl_scan(ctx, base + pos, n - pos, &digest, c_mask)
            if r == -2:
                raise Exception("goldilocks-aes: OpenSSL EVP encryption failed")
            if r < 0:
                break
            result.append(pos + <size_t>r)
            pos += <size_t>r + 1
        return result
    finally:
        gl_free(ctx)
