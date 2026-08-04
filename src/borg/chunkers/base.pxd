# cython: language_level=3

from libc.stdint cimport uint8_t, uint64_t, int64_t


cdef class ChunkerBase:
    # chunking parameters
    cdef str algo                 # chunker name, for error messages
    cdef uint64_t chunk_mask
    cdef uint64_t mask_s, mask_l  # normalized chunking: strict / loose masks
    cdef size_t normal_size       # chunk length at which we switch mask_s -> mask_l
    cdef int nc_level             # normalized chunking level (0 = disabled)

    # buffer and stream state
    cdef uint8_t* data
    cdef object _fd
    cdef int fh
    cdef int done, eof
    cdef size_t min_size, buf_size, remaining, position, last
    cdef long long bytes_read, bytes_yielded
    cdef readonly float chunking_time
    cdef object file_reader
    cdef size_t reader_block_size
    cdef bint sparse

    cdef int _setup_common(self, str algo, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits,
                           int nc_level, size_t normal_size, bint high_masks, bint sparse) except 0
    cdef int fill(self) except 0
    cdef object process(self)

    # hooks used by the shared (window-less) process(); overridden by subclasses.
    # window-based chunkers (buzhash64) override process() itself instead.
    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept
    cdef uint64_t _restart(self) noexcept
