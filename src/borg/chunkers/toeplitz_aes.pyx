# cython: language_level=3

import os
import cython

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.string cimport memset

from .phte_chunker cimport ChunkerPHTE

from ..crypto.low_level import CSPRNG


# toeplitz-aes: a "Chk-PHTE" style chunker (UHF-then-PRF, like rabin-aes and
# goldilocks-aes - see rabin_aes.pyx for the full motivation) whose UHF is a
# tabulated LFSR-based Toeplitz hash (Krawczyk, CRYPTO '94 - "LFSR-based
# hashing and authentication"):
#
#   1. the rolling *universal hash* over the 64-byte window is
#          digest = sum_j x^(63-j) * T[b_j]   over GF(2)[x] mod P,
#      where T is a secret random table of 256 uint64 values (2 KiB of key
#      material) and P is a FIXED PUBLIC irreducible polynomial of degree 64
#      (x^64 + x^4 + x^3 + x + 1, the x^64 bit implicit; the same polynomial
#      CLHASH uses for GF(2^64)). Two distinct windows collide with
#      probability EXACTLY 2^-64 over the choice of T: their difference is
#      sum_v c_v * T[v] with at least one coefficient c_v a nonzero
#      polynomial of degree < 64 - which mod an irreducible degree-64 P is an
#      invertible field element, making the sum uniform. This bound is
#      unconditional (P is public; no irreducibility sampling at setup) and
#      optimal for a 64-bit digest - better than rabin-aes (~2^-55) and
#      goldilocks-aes (~2^-58).
#      NOTE the window must be exactly 64 bytes: the argument needs distinct
#      powers x^0..x^63 of degree < 64 per position. (A plain-rotation
#      variant - keyed buzhash - fails here: rotations satisfy R^64 = I, so
#      e.g. two all-same-byte windows collide with probability 1/2.)
#   2. a *PRF* (AES-128 with a secret key) is applied to the digest; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(digest) & mask) == 0.
#
# Performance: same batching structure as rabin-aes (two even/odd rolling
# lanes, grouped AES). The rolling step is d' = d*x ^ x^64*T[out] ^ T[in],
# where d*x mod P is a shift plus a branchless masked XOR - and both table
# lookups are indexed by *plaintext* bytes. The serial dependency chain thus
# contains no memory loads at all (rabin-aes has a digest-indexed reduction
# lookup in its chain), which also means no secret-dependent memory access
# in the hot loop (cache-side-channel posture like goldilocks-aes).

cdef extern from "toeplitz_aes_impl.h":
    ctypedef struct TP_CTX:
        pass
    int TP_TABLES
    TP_CTX *tp_new(const uint64_t *tables, const uint8_t *aes_key, int kernel)
    int phte_kernel_select(const char *name, int *out_id)
    const char *phte_kernel_names()
    int PHTE_K_AUTO
    int PHTE_K_EVP
    void tp_free(TP_CTX *ctx)
    const char *tp_kind(const TP_CTX *ctx)
    uint64_t tp_digest64(const TP_CTX *ctx, const uint8_t *q)
    int64_t tp_scan(TP_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)


# --- GF(2)[x] helpers (pure Python, used at chunker setup only) ----------

# the fixed public irreducible polynomial P = x^64 + x^4 + x^3 + x + 1
_P = (1 << 64) | 0x1B
_WINDOW_SIZE = 64  # bytes; hard requirement of the collision bound, see above


def _poly_mod(v):
    """v mod P in GF(2)[x]."""
    while v.bit_length() - 1 >= 64:
        v ^= _P << (v.bit_length() - 1 - 64)
    return v


def _build_tables(t):
    """Build the rolling tables for T (order must match TP_TABLES in the C kernel).

    in0_tbl[b]   = T[b]                (incoming byte, newest position)
    in1_tbl[b]   = (x    * T[b]) mod P (stride-2, older incoming byte)
    out64_tbl[b] = (x^64 * T[b]) mod P (removal of the byte leaving the window)
    out65_tbl[b] = (x^65 * T[b]) mod P (stride-2 removal, older leaving byte)

    Tables 1..3 are algebraic combinations of T and P; they let the C kernel
    run two independent even/odd rolling lanes (see toeplitz_aes_impl.c)
    without changing any cut point.
    """
    in0_tbl = list(t)
    in1_tbl = [_poly_mod(v << 1) for v in t]
    out64_tbl = [_poly_mod(v << 64) for v in t]
    out65_tbl = [_poly_mod(v << 65) for v in t]
    return in0_tbl, in1_tbl, out64_tbl, out65_tbl


def _derive(bytes key):
    """Derive (aes_key, T, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then the
    table T as one 2048-byte block, split into 256 little-endian uint64.
    T must be uniform (not e.g. bit-balanced): the 2^-64 collision bound
    needs independent uniform entries.
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    blob = rng.random_bytes(8 * 256)
    t = [int.from_bytes(blob[8 * i : 8 * i + 8], "little") for i in range(256)]
    tables = _build_tables(t)
    return aes_key, t, tables


from .kernel_env import kernel_error, requested_kernel


cdef int _select_kernel() except -1:
    """Resolve BORG_AES_CHUNKER_KERNEL to a scan path id, raising if it cannot be honoured.

    One selector for all three AES chunkers: they share phte_scan.h, so the
    available paths never differ between them.
    """
    cdef int kid = PHTE_K_AUTO
    cdef int rc
    want = requested_kernel("BORG_AES_CHUNKER_KERNEL")
    if want is None:
        return PHTE_K_AUTO
    rc = phte_kernel_select(want.encode("ascii"), &kid)
    if rc != 0:
        raise kernel_error("BORG_AES_CHUNKER_KERNEL", want, rc,
                           (<bytes>phte_kernel_names()).decode("ascii"))
    return kid


cdef class ChunkerToeplitzAES(ChunkerPHTE):
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling tabulated Toeplitz hash (secret 2 KiB table, fixed public
    polynomial, 64-byte window) post-processed with AES-128; the cut decision
    only sees the AES output, so observed chunk boundaries do not leak usable
    information about the chunking secret (see module docstring).
    """
    cdef TP_CTX* ctx

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int nc_level=0, size_t normal_size=0, bint sparse=False):
        cdef uint64_t c_tables[4 * 256]
        cdef int i, t
        self.ctx = NULL
        self._setup("toeplitz-aes", chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level, normal_size, sparse)

        aes_key, table, tables = _derive(key)
        assert len(tables) == TP_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]

        kernel = _select_kernel()
        self.ctx = tp_new(c_tables, aes_key, kernel)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up toeplitz-aes kernel")
        self.kernel_str = (<bytes>tp_kind(self.ctx)).decode("ascii")

    def __dealloc__(self):
        if self.ctx != NULL:
            tp_free(self.ctx)
            self.ctx = NULL

    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept:
        return tp_scan(self.ctx, p, n, digest, mask)

    cdef uint64_t _digest64(self, const uint8_t *q) noexcept:
        return tp_digest64(self.ctx, q)


def toeplitz_aes_get_table(bytes key):
    """Get the secret table T derived from <key> (for tests)."""
    aes_key, t, tables = _derive(key)
    return t


def toeplitz_aes_get_tables(bytes key):
    """Get the (in0, in1, out64, out65) rolling tables derived from <key> (for tests)."""
    aes_key, t, tables = _derive(key)
    return tables


def toeplitz_aes_digest64(bytes key, bytes window):
    """C-kernel digest of a 64-byte window for the table derived from <key> (for tests).

    Lets tests verify the kernel's GF(2)[x] mod P arithmetic against a
    pure-Python big-int reference.
    """
    cdef uint64_t c_tables[4 * 256]
    cdef uint8_t aes_key_c[16]
    cdef TP_CTX *ctx
    cdef uint64_t d
    cdef int i, t
    assert len(window) == _WINDOW_SIZE
    aes_key, tt, tables = _derive(key)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    memset(aes_key_c, 0, 16)
    ctx = tp_new(c_tables, aes_key_c, PHTE_K_EVP)
    if ctx == NULL:
        raise MemoryError("Failed to set up toeplitz-aes kernel")
    d = tp_digest64(ctx, <const uint8_t*>PyBytes_AsString(window))
    tp_free(ctx)
    return d
