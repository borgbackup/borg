# cython: language_level=3

import os
import cython

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.string cimport memset

from .phte_chunker cimport ChunkerPHTE

from ..crypto.low_level import CSPRNG


# rabin-aes: a "Chk-PHTE" style content-defined chunker (UHF-then-PRF).
#
# Motivated by "Breaking and Fixing Content-Defined Chunking" (Truong, Merz,
# Scarlata, Guenther, Paterson; eprint 2025/558) and Alexeev/Percival/Zhang
# (arXiv 2504.02095): keyed chunkers built by hiding a secret inside a rolling
# hash (secret buzhash/gear tables) admit key-recovery attacks from known
# plaintext, because every observed cut is an equation about the secret.
# The provably sound construction separates the two jobs:
#
#   1. a rolling *universal hash function* (UHF) compresses the last w bytes
#      into a short digest; here: a Rabin fingerprint over GF(2)[x]/P(x) with
#      a secret random irreducible polynomial P of degree 64, over a 64-byte
#      window (the same UHF family restic uses, with a bigger polynomial).
#      P's degree-64 coefficient is implicit: the digest fills a uint64 and
#      the C kernel's left shifts naturally discard the reduced-away bits.
#   2. a *PRF* (AES-128 with a secret key) is applied to the digest; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(digest) & mask) == 0.
#
# An attacker who observes cut positions sees only PRF outputs; the digest and
# P remain hidden behind AES. Two windows colliding under the UHF is the only
# residual leakage (they necessarily get equal decisions); for a degree-64
# random irreducible P the collision probability of two distinct 64-byte
# windows is <= 511/2^63 ~= 2^-54.
#
# Security notes (honest limits):
#  * The FSWC-RoR proof bound (eprint 2025/558, Thm 4.5 analogue) degrades
#    with the square of the number of processed positions; with a 64-bit
#    digest it stays meaningful up to roughly tens of GiB per chunker key.
#    Beyond that, no *attack* is known - but the guarantee is heuristic, like
#    everything else in this area except a wider-digest construction.
#  * As with any deterministic chunker, equal chunks still produce equal
#    lengths (deduplication requires this); see the paper's discussion.
#
# Performance: the digest stream is independent of where cuts happen (each
# digest is a pure function of the last 64 bytes), so digests can be computed
# ahead and encrypted in batches. The C kernel (rabin_aes_impl.c) does this
# either via OpenSSL EVP AES-128-ECB batches (portable) or, where available,
# via AES instructions (arm64 crypto extension / x86-64 AES-NI) interleaved
# with the rolling-hash chain. All paths produce bit-identical cuts.

cdef extern from "rabin_aes_impl.h":
    ctypedef struct RA_CTX:
        pass
    int RA_TABLES
    RA_CTX *ra_new(const uint64_t *tables, const uint8_t *aes_key, int force_sw)
    void ra_free(RA_CTX *ctx)
    const char *ra_kind(const RA_CTX *ctx)
    uint64_t ra_digest64(const RA_CTX *ctx, const uint8_t *q)
    int64_t ra_scan(RA_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)


# --- GF(2)[x] polynomial helpers (pure Python, used at chunker setup only) ---

_DEG = 64  # degree of the secret irreducible polynomial P (top bit implicit in C)
_WINDOW_SIZE = 64  # bytes; window polynomial degree is 8 * 64 - 1 = 511

# spread table for GF(2) squaring: 8 bits -> 16 bits with zeros interleaved
_SPREAD8 = []
for _b in range(256):
    _s = 0
    for _i in range(8):
        if _b & (1 << _i):
            _s |= 1 << (2 * _i)
    _SPREAD8.append(_s)


def _poly_mod(v, p):
    """v mod p in GF(2)[x]; p must have its top bit set at degree deg(p)."""
    dp = p.bit_length() - 1
    while v.bit_length() - 1 >= dp:
        v ^= p << (v.bit_length() - 1 - dp)
    return v


def _poly_sq_mod(a, p):
    """a^2 mod p in GF(2)[x] (square = interleave zeros between bits)."""
    sq = 0
    shift = 0
    while a:
        sq |= _SPREAD8[a & 0xFF] << shift
        a >>= 8
        shift += 16
    return _poly_mod(sq, p)


def _poly_gcd(a, b):
    """gcd(a, b) in GF(2)[x]."""
    while b:
        a, b = b, _poly_mod(a, b)
    return a


def _is_irreducible(p):
    """Rabin's irreducibility test for deg(p) == 64 (prime factors of 64: 2).

    p is irreducible iff x^(2^64) == x (mod p) and gcd(x^(2^(64/2)) - x, p) == 1,
    i.e. for the exponent 32.
    """
    assert p.bit_length() - 1 == _DEG
    x = 2  # the polynomial "x"
    r = x
    saved = {}
    for i in range(1, _DEG + 1):
        r = _poly_sq_mod(r, p)
        if i == 32:
            saved[i] = r
    if r != x:
        return False
    if _poly_gcd(p, saved[32] ^ x) != 1:
        return False
    return True


def _sample_polynomial(rng):
    """Sample a random irreducible polynomial of degree 64 from the CSPRNG.

    The polynomial has its degree-64 and constant coefficients set; the 63
    middle coefficients are random. About 1 in 64 candidates is irreducible.
    """
    while True:
        v = int.from_bytes(rng.random_bytes(8), "little")
        p = (1 << _DEG) | (v & ((1 << _DEG) - 2)) | 1
        if _is_irreducible(p):
            return p


def _build_tables(p):
    """Build the rolling tables for P (order must match RA_TABLES in the C kernel).

    out_tbl[b]   = poly(b) * x^504 mod P  (remove the byte leaving the window;
                                           504 = 8 * (window_size - 1))
    red_tbl[t]   = poly(t) * x^64 mod P   (reduce the 8 bits shifted above bit 63)
    w1_tbl[t]    = poly(t) * x^72 mod P   (stride-2 step: reduce bits 72..79)
    out8_tbl[b]  = poly(b) * x^512 mod P  (stride-2 removal, newer byte)
    out16_tbl[b] = poly(b) * x^520 mod P  (stride-2 removal, older byte)

    The last three are algebraic combinations of the first two; they let the C
    kernel run two independent even/odd rolling lanes (see rabin_aes_impl.c)
    without changing any cut point.
    """
    out_tbl = [_poly_mod(b << (8 * (_WINDOW_SIZE - 1)), p) for b in range(256)]
    red_tbl = [_poly_mod(t << _DEG, p) for t in range(256)]
    w1_tbl = [_poly_mod(t << (_DEG + 8), p) for t in range(256)]
    out8_tbl = [_poly_mod(b << (8 * _WINDOW_SIZE), p) for b in range(256)]
    out16_tbl = [_poly_mod(b << (8 * (_WINDOW_SIZE + 1)), p) for b in range(256)]
    return out_tbl, red_tbl, w1_tbl, out8_tbl, out16_tbl


def _derive(bytes key):
    """Derive (aes_key, P, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then P
    (8 bytes per candidate until irreducible).
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    p = _sample_polynomial(rng)
    tables = _build_tables(p)
    return aes_key, p, tables


cdef class ChunkerRabinAES(ChunkerPHTE):
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling Rabin fingerprint (secret irreducible polynomial, 64-byte window)
    post-processed with AES-128; the cut decision only sees the AES output,
    so observed chunk boundaries do not leak usable information about the
    chunking secret (see module docstring).
    """
    cdef RA_CTX* ctx

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int nc_level=0, size_t normal_size=0, bint sparse=False):
        cdef uint64_t c_tables[5 * 256]
        cdef int i, t
        self.ctx = NULL
        self._setup("rabin-aes", chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level, normal_size, sparse)

        aes_key, p, tables = _derive(key)
        assert len(tables) == RA_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]

        force_sw = os.environ.get("BORG_RABIN_AES_FORCE_EVP", "") not in ("", "0")
        self.ctx = ra_new(c_tables, aes_key, 1 if force_sw else 0)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up rabin-aes kernel")
        self.kernel_str = (<bytes>ra_kind(self.ctx)).decode("ascii")

    def __dealloc__(self):
        if self.ctx != NULL:
            ra_free(self.ctx)
            self.ctx = NULL

    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept:
        return ra_scan(self.ctx, p, n, digest, mask)

    cdef uint64_t _digest64(self, const uint8_t *q) noexcept:
        return ra_digest64(self.ctx, q)


def rabin_aes_get_polynomial(bytes key):
    """Get the secret irreducible polynomial P derived from <key> (for tests)."""
    aes_key, p, tables = _derive(key)
    return p


def rabin_aes_get_tables(bytes key):
    """Get the (out_tbl, red_tbl) rolling tables derived from <key> (for tests)."""
    aes_key, p, tables = _derive(key)
    return tables[0], tables[1]
