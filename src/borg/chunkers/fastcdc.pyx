# cython: language_level=3

import os

import cython

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.stdlib cimport malloc, free

from ..crypto.low_level import CSPRNG

from .base cimport ChunkerBase

cdef extern from "fastcdc_impl.h":
    int64_t fc_scan(const uint64_t *gear, const uint8_t *p, size_t n, uint64_t *fp, uint64_t mask, int force_scalar) nogil
    const char *fc_kernel_name(int force_scalar)

# FastCDC content-defined chunker (Xia et al., USENIX ATC 2016).
#
# Differences vs. the buzhash64 chunker in this package:
#  * It uses the Gear rolling hash: fp = (fp << 1) + Gear[byte]. This is a single shift,
#    add and table lookup per byte (no window, no "remove" term), so it is cheaper than
#    buzhash's cyclic-polynomial update.
#  * The Gear table is keyed from a 256-bit key via the same CSPRNG used by buzhash64, so
#    cut points are unpredictable without the key (anti-fingerprinting), just like buzhash64.
#  * Because the Gear hash accumulates information in its HIGH bits (the low bits only depend
#    on the most recent bytes), the cut-decision mask uses the high bits of the hash.
#
# It implements the same FastCDC techniques the buzhash64 chunker uses: sub-minimum cut-point
# skipping, normalized chunking (strict/loose mask around a "normal" size), and min/max clamping.
# All of that - buffering, the scan loop, sparse/hole handling - lives in ChunkerBase; this
# class only provides the keyed Gear table and the _scan() hook calling the C kernel.
#
# The inner scan runs in a C kernel (fastcdc_impl.c) with SIMD implementations (NEON on
# aarch64, AVX-512 or AVX2 on x86-64, blocked scalar elsewhere) that are bit-identical to
# the plain sequential Gear loop: every byte position is tested, cuts and hash state are
# exactly the same, only faster. BORG_FASTCDC_FORCE_SCALAR=1 forces the sequential loop
# (for tests); BORG_FASTCDC_NO_AVX512=1 caps dispatch at AVX2 and BORG_FASTCDC_NO_AVX2=1
# at the blocked scalar kernel (for benchmarking, must be set before the first chunker use).


@cython.boundscheck(False)
@cython.wraparound(False)
cdef uint64_t* fastcdc_init_gear(bytes key) except NULL:
    """Generate a keyed 256-entry, 64-bit Gear table deterministically from a 256-bit key."""
    rng = CSPRNG(key)
    cdef bytes rnd = rng.random_bytes(2048)  # 256 * sizeof(uint64_t)
    cdef const uint8_t* rp = <const uint8_t*>PyBytes_AsString(rnd)
    cdef uint64_t* gear = <uint64_t*>malloc(2048)
    if gear == NULL:
        raise MemoryError("Failed to allocate fastcdc gear table")
    cdef int i, j
    cdef uint64_t v
    for i in range(256):
        v = 0
        for j in range(8):
            v |= (<uint64_t>rp[i * 8 + j]) << (8 * j)
        gear[i] = v
    return gear


cdef class ChunkerFastCDC(ChunkerBase):
    """
    FastCDC content-defined chunker, variable chunk sizes, keyed Gear hash.

    Unlike the buzhash chunkers, Gear is window-less, so there is no hash_window_size parameter.
    """
    cdef uint64_t* gear
    cdef int force_scalar

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int nc_level=0, size_t normal_size=0, bint sparse=False):
        self.gear = NULL
        self.force_scalar = 1 if os.environ.get("BORG_FASTCDC_FORCE_SCALAR", "") not in ("", "0") else 0
        self.gear = fastcdc_init_gear(key)
        # Gear accumulates information in its high bits, so the cut-decision
        # masks must use the high bits of the hash (high_masks=True). The Gear
        # hash restarts from 0 at each chunk (window-less), so the default
        # _restart() is correct.
        self._setup_common("fastcdc", chunk_min_exp, chunk_max_exp, hash_mask_bits,
                           nc_level, normal_size, True, sparse)

    def __dealloc__(self):
        if self.gear != NULL:
            free(self.gear)
            self.gear = NULL

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'neon', 'avx512', 'avx2', 'blocked' or 'scalar'."""
        return (<bytes>fc_kernel_name(self.force_scalar)).decode("ascii")

    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept:
        cdef int64_t r
        with nogil:
            r = fc_scan(self.gear, p, n, digest, mask, self.force_scalar)
        return r


def fastcdc_get_gear_table(bytes key):
    """Get the keyed gear table generated from <key> (for tests / inspection)."""
    cdef uint64_t* gear = fastcdc_init_gear(key)
    cdef int i
    try:
        return [gear[i] for i in range(256)]
    finally:
        free(gear)
