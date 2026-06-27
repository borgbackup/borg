# cython: language_level=3

import cython
import time

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memmove, memset

from ..crypto.low_level import CSPRNG

from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros
from .reader import FileReader, Chunk

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


cdef inline uint64_t _high_mask(int bits):
    """A mask with <bits> one-bits in the most significant positions (Gear's strong bits)."""
    if bits <= 0:
        return 0
    if bits >= 64:
        return <uint64_t>0xFFFFFFFFFFFFFFFF
    return ((<uint64_t>1 << bits) - 1) << (64 - bits)


cdef class ChunkerFastCDC:
    """
    FastCDC content-defined chunker, variable chunk sizes, keyed Gear hash.

    Unlike the buzhash chunkers, Gear is window-less, so there is no hash_window_size parameter.
    """
    cdef uint64_t chunk_mask
    cdef uint64_t mask_s, mask_l  # normalized chunking: strict / loose masks
    cdef size_t normal_size       # chunk length at which we switch mask_s -> mask_l
    cdef int nc_level             # normalized chunking level (0 = disabled)
    cdef uint64_t* gear
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

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int nc_level=0, size_t normal_size=0, bint sparse=False):
        self.gear = NULL
        self.data = NULL
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        assert min_size + 1 <= max_size, "too small max_size"

        self.chunk_mask = _high_mask(hash_mask_bits)
        self.min_size = min_size
        # Normalized chunking, identical structure to the buzhash64 chunker (see there), but with
        # the mask one-bits placed in the high bits of the Gear hash.
        assert nc_level >= 0
        assert hash_mask_bits - nc_level >= 1, "nc_level too large for hash_mask_bits"
        assert hash_mask_bits + nc_level <= 48, "nc_level too large for hash_mask_bits"
        self.nc_level = nc_level
        if nc_level:
            self.mask_s = _high_mask(hash_mask_bits + nc_level)
            self.mask_l = _high_mask(hash_mask_bits - nc_level)
            self.normal_size = normal_size if normal_size else ((1ULL << hash_mask_bits) - (1ULL << (hash_mask_bits - nc_level)))
        else:
            self.mask_s = self.chunk_mask
            self.mask_l = self.chunk_mask
            self.normal_size = 0
        self.gear = fastcdc_init_gear(key)
        self.buf_size = max_size
        self.data = <uint8_t*>malloc(self.buf_size)
        if self.data == NULL:
            raise MemoryError("Failed to allocate chunker buffer")
        self.fh = -1
        self.done = 0
        self.eof = 0
        self.remaining = 0
        self.position = 0
        self.last = 0
        self.bytes_read = 0
        self.bytes_yielded = 0
        self._fd = None
        self.chunking_time = 0.0
        self.reader_block_size = 1024 * 1024
        self.sparse = sparse

    def __dealloc__(self):
        if self.gear != NULL:
            free(self.gear)
            self.gear = NULL
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    cdef int fill(self) except 0:
        """Fill the chunker's buffer with more data."""
        cdef ssize_t n
        cdef object chunk

        memmove(self.data, self.data + self.last, self.position + self.remaining - self.last)
        self.position -= self.last
        self.last = 0
        n = self.buf_size - self.position - self.remaining

        if self.eof or n == 0:
            return 1

        chunk = self.file_reader.read(n)
        n = chunk.meta["size"]

        if n > 0:
            if chunk.meta["allocation"] == CH_DATA:
                memcpy(self.data + self.position + self.remaining, <const unsigned char*>PyBytes_AsString(chunk.data), n)
            else:
                memset(self.data + self.position + self.remaining, 0, n)
            self.remaining += n
            self.bytes_read += n
        else:
            self.eof = 1
        return 1

    cdef object process(self) except *:
        """Process the chunker's buffer and return the next chunk."""
        cdef uint64_t fp = 0, mask, mask_s = self.mask_s, mask_l = self.mask_l
        cdef int nc_level = self.nc_level
        cdef size_t n, old_last, min_size = self.min_size
        cdef size_t normal_size = self.normal_size, normal_pos, chunk_len, did
        cdef uint8_t* p
        cdef uint8_t* stop
        cdef uint8_t* cut
        cdef uint64_t* gear = self.gear

        if self.done:
            if self.bytes_read == self.bytes_yielded:
                raise StopIteration
            else:
                raise Exception("chunkifier byte count mismatch")

        # ensure at least min_size + 1 bytes are buffered, or we are at eof
        while self.remaining < min_size + 1 and not self.eof:
            if not self.fill():
                return None

        # at eof with only a remainder (< min_size + 1): emit it as the final chunk
        if self.eof and self.remaining < min_size + 1:
            self.done = 1
            if self.remaining:
                old_last = self.last
                self.position += self.remaining
                self.last = self.position
                n = self.last - old_last
                self.remaining = 0
                self.bytes_yielded += n
                return memoryview((self.data + old_last)[:n])
            else:
                if self.bytes_read == self.bytes_yielded:
                    raise StopIteration
                else:
                    raise Exception("chunkifier byte count mismatch")

        # skip the sub-minimum region (no cut allowed below min_size), then gear-scan
        self.position += min_size
        self.remaining -= min_size
        fp = 0

        while True:
            chunk_len = self.position - self.last
            mask = mask_s if (nc_level and chunk_len < normal_size) else mask_l

            if self.remaining == 0:
                if self.eof:
                    break  # cut at end of data
                if not self.fill():
                    return None
                if self.remaining == 0:
                    break  # buffer full -> chunk reached max_size -> forced cut
                continue

            p = self.data + self.position
            stop = p + self.remaining
            if nc_level and chunk_len < normal_size:
                # do not scan past the strict->loose transition; re-evaluate the mask there
                normal_pos = self.last + normal_size
                if (self.data + normal_pos) < stop:
                    stop = self.data + normal_pos

            cut = NULL
            while p < stop:
                fp = (fp << 1) + gear[p[0]]
                if (fp & mask) == 0:
                    cut = p
                    break
                p += 1

            if cut != NULL:
                p = cut + 1  # cut right after the byte that triggered the boundary
                did = p - (self.data + self.position)
                self.position += did
                self.remaining -= did
                break
            else:
                did = p - (self.data + self.position)
                self.position += did
                self.remaining -= did

        old_last = self.last
        self.last = self.position
        n = self.last - old_last
        self.bytes_yielded += n
        return memoryview((self.data + old_last)[:n])

    def chunkify(self, fd, fh=-1, fmap=None):
        self._fd = fd
        self.fh = fh
        self.file_reader = FileReader(fd=fd, fh=fh, read_size=self.reader_block_size, sparse=self.sparse, fmap=fmap)
        self.done = 0
        self.remaining = 0
        self.bytes_read = 0
        self.bytes_yielded = 0
        self.position = 0
        self.last = 0
        self.eof = 0
        return self

    def __iter__(self):
        return self

    def __next__(self):
        started_chunking = time.monotonic()
        data = self.process()
        got = len(data)
        if zeros.startswith(data):
            data = None
            allocation = CH_ALLOC
        else:
            allocation = CH_DATA
        self.chunking_time += time.monotonic() - started_chunking
        return Chunk(data, size=got, allocation=allocation)


def fastcdc_get_gear_table(bytes key):
    """Get the keyed gear table generated from <key> (for tests / inspection)."""
    cdef uint64_t* gear = fastcdc_init_gear(key)
    cdef int i
    try:
        return [gear[i] for i in range(256)]
    finally:
        free(gear)
