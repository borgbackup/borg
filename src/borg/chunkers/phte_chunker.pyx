# cython: language_level=3

from libc.stdint cimport uint8_t, uint64_t

from .base cimport ChunkerBase

# Shared chunker driver for the "UHF-then-PRF" (Chk-PHTE) chunkers: rabin-aes,
# goldilocks-aes and toeplitz-aes. They differ only in their rolling universal
# hash, which lives in their C kernels (see phte_core.h / phte_scan.h) and in
# the key derivation in their own modules. Buffering, min/max clamping,
# normalized chunking and the scan loop live in ChunkerBase; this class adds
# the 64-byte-window digest warm-up and the kernel-name plumbing.
#
# Subclasses implement _scan() and _digest64() by calling their C kernel. Both
# are Cython cdef methods, i.e. one vtable-dispatched call per *scan span*
# (up to a whole chunk of data) and per chunk start - never per byte, so the
# indirection is not measurable.


cdef class ChunkerPHTE(ChunkerBase):
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Base class: a rolling universal hash compresses the last 64 bytes into a
    digest, AES-128 with a secret key is applied to it, and the cut decision
    only looks at the AES output. See the subclasses for the concrete
    universal hash and the security discussion.
    """

    cdef int _setup(self, str algo, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits,
                    int nc_level, size_t normal_size, bint sparse) except 0:
        """Set up chunking parameters and the buffer (called by the subclass)."""
        # the rolling window needs 64 bytes of in-chunk history at the first
        # possible cut position (min_size), so the minimum chunk size must be
        # at least the window size:
        assert chunk_min_exp >= 6, "chunk_min_exp must be >= 6 (2^6 = 64 = window size)"
        self.kernel_str = "unknown"
        # the AES output is uniform, so contiguous low-bit masks are fine
        return self._setup_common(algo, chunk_min_exp, chunk_max_exp, hash_mask_bits,
                                  nc_level, normal_size, False, sparse)

    cdef uint64_t _digest64(self, const uint8_t *q) noexcept:
        """Digest of the 64 bytes at q (window warm-up). Implemented by subclasses."""
        return 0

    cdef uint64_t _restart(self) noexcept:
        # warm up the rolling digest over the 64 bytes preceding the first
        # scan position (they are within the current chunk, since min_size >= 64).
        return self._digest64(self.data + self.position - 64)

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'vaes', 'aes-ni', 'aes-arm64' or 'evp'."""
        return self.kernel_str
