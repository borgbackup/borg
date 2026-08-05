# cython: language_level=3

from libc.stdint cimport uint8_t, uint64_t

from .base cimport ChunkerBase


cdef class ChunkerPHTE(ChunkerBase):
    cdef str kernel_str           # scan kernel the subclass selected

    cdef int _setup(self, str algo, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits,
                    int nc_level, size_t normal_size, bint sparse) except 0

    # implemented by the subclasses, calling into their C kernel
    cdef uint64_t _digest64(self, const uint8_t *q) noexcept
