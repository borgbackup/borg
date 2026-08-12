# cython: language_level=3



import os

import cython

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t
from libc.stdlib cimport malloc, free

from ..crypto.low_level import CSPRNG

from .base cimport ChunkerBase

cdef extern from "buzhash64_impl.h":
    size_t bz64_scan(const uint64_t *table, const uint64_t *table_rot,
                     const uint8_t *p_rem, const uint8_t *p_add,
                     size_t n, uint64_t *sum, uint64_t mask, int kernel) nogil
    const char *bz64_kernel_name(int kernel)
    int bz64_kernel_select(const char *name, int *out_id)
    const char *bz64_kernel_names()
    int BZ_K_SCALAR

from .kernel_env import kernel_error, requested_kernel

# Cyclic polynomial / buzhash
#
# https://en.wikipedia.org/wiki/Rolling_hash
#
# http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.012.html (by "BUZ", the inventor)
#
# http://www.dcs.gla.ac.uk/~hamer/cakes-talk.pdf (see buzhash slide)
#
# Some properties of buzhash / of this implementation:
#
# (1) the hash is designed for inputs <= 64 bytes, but the chunker uses it on a 4095 byte window;
#     any repeating bytes at distance 64 within those 4095 bytes can cause cancellation within
#     the hash function, e.g. in "X <any 63 bytes> X", the last X would cancel out the influence
#     of the first X on the hash value.

# This seems to be the most reliable way to inline this code, using a C preprocessor macro:
cdef extern from *:
   """
   #define BARREL_SHIFT64(v, shift) (((v) << (shift)) | ((v) >> (((64 - (shift)) & 0x3f))))
   """
   uint64_t BARREL_SHIFT64(uint64_t v, uint64_t shift) nogil


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
cdef uint64_t* buzhash64_init_table(bytes key) except NULL:
    """
    Generate a balanced pseudo-random table deterministically from a 256-bit key.
    Balanced means that for each bit position 0..63, exactly 50% of the table values have the bit set to 1.
    """
    # Create deterministic random number generator
    rng = CSPRNG(key)

    cdef int i, j, bit_pos
    cdef uint64_t* table = <uint64_t*>malloc(2048)  # 256 * sizeof(uint64_t)
    if table == NULL:
        raise MemoryError("Failed to allocate buzhash64 table")

    # Initialize all values to 0
    for i in range(256):
        table[i] = 0

    # For each bit position, deterministically assign exactly 128 positions to have that bit set
    for bit_pos in range(64):
        # Create a list of indices and shuffle deterministically
        indices = list(range(256))
        rng.shuffle(indices)

        # Set the bit at bit_pos for the first 128 shuffled indices
        for i in range(128):
            j = indices[i]
            table[j] |= (1ULL << bit_pos)

    return table


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint64_t _buzhash64(const unsigned char* data, size_t len, const uint64_t* h) noexcept nogil:
    """Calculate the buzhash of the given data."""
    cdef uint64_t i
    cdef uint64_t sum = 0, imod
    if len == 0:
        return 0
    for i in range(len - 1, 0, -1):
        imod = i & 0x3f
        sum ^= BARREL_SHIFT64(h[data[0]], imod)
        data += 1
    return sum ^ h[data[0]]


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint64_t _buzhash64_update(uint64_t sum, unsigned char remove, unsigned char add, size_t len, const uint64_t* h) noexcept nogil:
    """Update the buzhash with a new byte."""
    cdef uint64_t lenmod = len & 0x3f
    return BARREL_SHIFT64(sum, 1) ^ BARREL_SHIFT64(h[remove], lenmod) ^ h[add]


cdef int _select_kernel() except -1:
    """Resolve BORG_BUZHASH64_KERNEL to a kernel id, raising if it cannot be honoured.

    Unset means the simplest implementation, not the fastest one: nothing here
    guesses which kernel a given CPU and compiler make fastest.
    """
    cdef int kid = BZ_K_SCALAR
    cdef int rc
    want = requested_kernel("BORG_BUZHASH64_KERNEL")
    if want is None:
        return BZ_K_SCALAR
    rc = bz64_kernel_select(want.encode("ascii"), &kid)
    if rc != 0:
        raise kernel_error("BORG_BUZHASH64_KERNEL", want, rc,
                           (<bytes>bz64_kernel_names()).decode("ascii"))
    return kid


cdef class ChunkerBuzHash64(ChunkerBase):
    """
    Content-Defined Chunker, variable chunk sizes.

    This chunker makes quite some effort to cut mostly chunks of the same-content, even if
    the content moves to a different offset inside the file. It uses the buzhash
    rolling-hash algorithm to identify the chunk cutting places by looking at the
    content inside the moving window and computing the rolling hash value over the
    window contents. If the last n bits of the rolling hash are 0, a chunk is cut.
    Additionally it obeys some more criteria, like a minimum and maximum chunk size.
    It also uses a per-repo random seed to avoid some chunk length fingerprinting attacks.

    Buffering and iteration live in ChunkerBase; the window-based scan loop needs its
    own process() (the shared one is for window-less hashes).
    """
    cdef uint64_t* table
    cdef uint64_t* table_rot
    cdef int kernel_id
    cdef size_t window_size

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int hash_window_size, int nc_level=0, size_t normal_size=0, bint sparse=False):
        cdef int i_rot
        cdef uint64_t lenmod
        self.table = NULL
        self.table_rot = NULL
        # see process, first while loop condition, first term must be able to get True:
        assert hash_window_size + (1 << chunk_min_exp) + 1 <= (1 << chunk_max_exp), "too small max_size"

        self.window_size = hash_window_size
        self.table = buzhash64_init_table(key)
        # precomputed ROTL(table[b], window_size % 64): saves one rotate per byte
        # in the scan kernels (bit-identical, see buzhash64_impl.c)
        self.table_rot = <uint64_t*>malloc(2048)
        if self.table_rot == NULL:
            raise MemoryError("Failed to allocate buzhash64 rotated table")
        lenmod = <uint64_t>hash_window_size & 0x3f
        for i_rot in range(256):
            self.table_rot[i_rot] = BARREL_SHIFT64(self.table[i_rot], lenmod)
        self.kernel_id = _select_kernel()
        # buzhash64 output is uniform, so contiguous low-bit masks are used (high_masks=False)
        self._setup_common("buzhash64", chunk_min_exp, chunk_max_exp, hash_mask_bits,
                           nc_level, normal_size, False, sparse)

    def __dealloc__(self):
        """Free the chunker's resources."""
        if self.table != NULL:
            free(self.table)
            self.table = NULL
        if self.table_rot != NULL:
            free(self.table_rot)
            self.table_rot = NULL

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'neon', 'avx512', 'avx2', 'blockwise' or 'scalar'.

        'scalar' unless BORG_BUZHASH64_KERNEL names another one, in which case
        this is always that one - creating the chunker fails otherwise.
        """
        return (<bytes>bz64_kernel_name(self.kernel_id)).decode("ascii")

    cdef object process(self):
        """Process the chunker's buffer and return the next chunk."""
        cdef uint64_t sum, mask
        cdef uint64_t mask_s = self.mask_s, mask_l = self.mask_l
        cdef int nc_level = self.nc_level
        cdef size_t n, old_last, min_size = self.min_size, window_size = self.window_size
        cdef size_t normal_size = self.normal_size, normal_pos
        cdef uint8_t* p
        cdef uint8_t* stop_at
        cdef uint8_t* nc_stop
        cdef size_t did_bytes, span
        cdef int kernel_id = self.kernel_id

        if self.done:
            if self.bytes_read == self.bytes_yielded:
                raise StopIteration
            else:
                raise Exception("chunkifier byte count mismatch")

        while self.remaining < min_size + window_size + 1 and not self.eof:  # see assert in Chunker init
            self.fill()

        # Here we either are at eof...
        if self.eof:
            self.done = 1
            if self.remaining:
                self.bytes_yielded += self.remaining
                # Return a memory view of the remaining data
                return memoryview((self.data + self.position)[:self.remaining])
            else:
                if self.bytes_read == self.bytes_yielded:
                    raise StopIteration
                else:
                    raise Exception("chunkifier byte count mismatch")

        # ... or we have at least min_size + window_size + 1 bytes remaining.
        # We do not want to "cut" a chunk smaller than min_size and the hash
        # window starts at the potential cutting place.
        self.position += min_size
        self.remaining -= min_size
        with nogil:
            sum = _buzhash64(self.data + self.position, window_size, self.table)

        # Normalized chunking: pick the mask based on how far we are into the current chunk.
        # While below normal_size use the strict mask (lower cut probability), afterward the
        # loose mask (higher cut probability). The mask is re-evaluated at the top of every
        # iteration, so the transition is honored exactly at normal_pos. When nc is disabled,
        # mask_s == mask_l == chunk_mask and the normal_pos cap is not applied, so this reduces
        # to the original single-mask behavior.
        mask = mask_s
        normal_pos = 0
        while True:
            if nc_level:
                normal_pos = self.last + normal_size
                mask = mask_s if self.position < normal_pos else mask_l

            if not (self.remaining > window_size and (sum & mask) and not (self.eof and self.remaining <= window_size)):
                break

            p = self.data + self.position
            stop_at = p + self.remaining - window_size

            if nc_level and self.position < normal_pos:
                # do not scan past the strict->loose transition; re-evaluate the mask there
                nc_stop = self.data + normal_pos
                if nc_stop < stop_at:
                    stop_at = nc_stop

            span = stop_at - p
            with nogil:
                did_bytes = bz64_scan(self.table, self.table_rot, p, p + window_size,
                                      span, &sum, mask, kernel_id)
            self.position += did_bytes
            self.remaining -= did_bytes

            if self.remaining <= window_size:
                self.fill()

        if self.remaining <= window_size:
            self.position += self.remaining
            self.remaining = 0

        old_last = self.last
        self.last = self.position
        n = self.last - old_last
        self.bytes_yielded += n

        # Return a memory view of the chunk
        return memoryview((self.data + old_last)[:n])


def buzhash64(data, bytes key):
    cdef uint64_t *table
    cdef uint64_t sum
    table = buzhash64_init_table(key)
    sum = _buzhash64(<const unsigned char *> data, len(data), table)
    free(table)
    return sum


def buzhash64_update(uint64_t sum, unsigned char remove, unsigned char add, size_t len, bytes key):
    cdef uint64_t *table
    table = buzhash64_init_table(key)
    sum = _buzhash64_update(sum, remove, add, len, table)
    free(table)
    return sum


def buzhash64_get_table(bytes key):
    """Get the buzhash table generated from <key>."""
    cdef uint64_t *table
    cdef int i
    table = buzhash64_init_table(key)
    try:
        return [table[i] for i in range(256)]
    finally:
        free(table)
