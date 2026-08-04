# cython: language_level=3

import time

from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memmove

from ..constants import CH_DATA, CH_ALLOC, zeros
from .reader import FileReader, Chunk

# Common driver for all content-defined chunkers: buffering, min/max clamping,
# normalized chunking parameters, sparse/hole handling and the iterator
# protocol are implemented here once.
#
# Subclasses either use the shared window-less process() by overriding the
# _scan() / _restart() hooks (fastcdc, and ChunkerPHTE for the AES chunkers),
# or override process() as a whole (window-based chunkers like buzhash64).
# The hooks are Cython cdef methods, i.e. one vtable-dispatched call per
# *scan span* (up to a whole chunk of data) and per chunk start - never per
# byte, so the indirection is not measurable.


cdef inline uint64_t _mask_bits(int bits, bint high):
    """A mask with <bits> one-bits, in the least or most significant positions."""
    cdef uint64_t low
    if bits <= 0:
        return 0
    if bits >= 64:
        return <uint64_t>0xFFFFFFFFFFFFFFFF
    low = (<uint64_t>1 << bits) - 1
    return (low << (64 - bits)) if high else low


cdef class ChunkerBase:
    """
    Content-Defined Chunker base class: buffer and stream handling.

    Subclasses implement the cut decision, either via the _scan()/_restart()
    hooks (using the shared process()) or by overriding process().
    """

    cdef int _setup_common(self, str algo, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits,
                           int nc_level, size_t normal_size, bint high_masks, bint sparse) except 0:
        """Set up chunking parameters and the buffer (called by the subclass's __cinit__).

        high_masks selects where the cut-decision mask one-bits are placed: the low bits
        (hashes with uniform output, e.g. buzhash64 or the AES chunkers) or the high bits
        (Gear-style hashes, which accumulate information in their high bits).
        """
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        assert min_size + 1 <= max_size, "too small max_size"

        self.algo = algo
        self.chunk_mask = _mask_bits(hash_mask_bits, high_masks)
        self.min_size = min_size
        # Normalized chunking (FastCDC-style): use a stricter mask (lower cut probability)
        # until the chunk reaches its expected/normal size, then a looser mask (higher cut
        # probability). This concentrates chunk sizes around the target and reduces
        # chunk-size variance. nc_level == 0 disables it, keeping behavior byte-identical
        # to the single-mask chunker.
        assert nc_level >= 0
        assert hash_mask_bits - nc_level >= 1, "nc_level too large for hash_mask_bits"
        assert hash_mask_bits + nc_level <= 48, "nc_level too large for hash_mask_bits"
        self.nc_level = nc_level
        if nc_level:
            self.mask_s = _mask_bits(hash_mask_bits + nc_level, high_masks)
            self.mask_l = _mask_bits(hash_mask_bits - nc_level, high_masks)
            # normal_size is the chunk length at which we switch from the strict to the loose
            # mask; it dominates the mean chunk size. The default is the nominal target size
            # (1ULL << hash_mask_bits) minus the expected loose-phase tail (1ULL << (bits - nc_level)),
            # which lands the mean close to the target instead of overshooting it. Pass an
            # explicit normal_size to tune it further.
            self.normal_size = normal_size if normal_size else ((1ULL << hash_mask_bits) - (1ULL << (hash_mask_bits - nc_level)))
        else:
            self.mask_s = self.chunk_mask
            self.mask_l = self.chunk_mask
            self.normal_size = 0

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
        return 1

    def __dealloc__(self):
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    cdef int64_t _scan(self, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask) noexcept:
        """Scan n positions for a cut point. Implemented by subclasses using the shared process()."""
        return -1

    cdef uint64_t _restart(self) noexcept:
        """Hash/digest state at the first scan position of a new chunk (at self.position,
        which is min_size into the chunk). Window-less hashes restart from 0 (the default);
        windowed hashes warm up over the preceding bytes."""
        return 0

    cdef int fill(self) except 0:
        """Fill the chunker's buffer with more data."""
        cdef ssize_t n

        # Move remaining data to the beginning of the buffer
        with nogil:
            memmove(self.data, self.data + self.last, self.position + self.remaining - self.last)
        self.position -= self.last
        self.last = 0
        n = self.buf_size - self.position - self.remaining

        if self.eof or n == 0:
            return 1

        if n > 0:
            # zero-copy path: the reader writes file data (and zeros for holes)
            # directly into the scan buffer - one memcpy per byte instead of
            # slice/join/copy chains through intermediate bytes objects.
            n = self.file_reader.readinto(
                <uint8_t[:n]>(self.data + self.position + self.remaining), n)
        if n > 0:
            self.remaining += n
            self.bytes_read += n
        else:
            self.eof = 1
        return 1

    cdef object process(self):
        """Process the chunker's buffer and return the next chunk."""
        cdef uint64_t digest = 0, mask, mask_s = self.mask_s, mask_l = self.mask_l
        cdef int nc_level = self.nc_level
        cdef size_t n, old_last, min_size = self.min_size
        cdef size_t normal_size = self.normal_size, normal_pos, chunk_len, span, did
        cdef int64_t r
        cdef uint8_t* p
        cdef uint8_t* stop

        if self.done:
            if self.bytes_read == self.bytes_yielded:
                raise StopIteration
            else:
                raise Exception("chunkifier byte count mismatch")

        # ensure at least min_size + 1 bytes are buffered, or we are at eof
        while self.remaining < min_size + 1 and not self.eof:
            self.fill()

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

        # skip the sub-minimum region (no cut allowed below min_size), then scan
        self.position += min_size
        self.remaining -= min_size
        digest = self._restart()

        while True:
            chunk_len = self.position - self.last
            mask = mask_s if (nc_level and chunk_len < normal_size) else mask_l

            if self.remaining == 0:
                if self.eof:
                    break  # cut at end of data
                self.fill()
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

            span = stop - p
            r = self._scan(p, span, &digest, mask)
            if r == -2:
                raise Exception(f"{self.algo}: OpenSSL EVP encryption failed")
            if r >= 0:
                did = <size_t>r + 1  # cut right after the position that matched
                self.position += did
                self.remaining -= did
                break
            else:
                self.position += span
                self.remaining -= span

        old_last = self.last
        self.last = self.position
        n = self.last - old_last
        self.bytes_yielded += n
        return memoryview((self.data + old_last)[:n])

    def chunkify(self, fd, fh=-1, fmap=None):
        """
        Cut a file into chunks.

        :param fd: Python file object
        :param fh: OS-level file handle (if available),
                   defaults to -1 which means not to use OS-level fd.
        :param fmap: a file map, same format as generated by sparsemap
        """
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
        # we do not know whether the data came from a hole in a sparse file,
        # but we can just check if it was all-zero (and either came from a hole
        # or from stored zeros - we can not detect that here).
        if zeros.startswith(data):
            data = None
            allocation = CH_ALLOC
        else:
            allocation = CH_DATA
        self.chunking_time += time.monotonic() - started_chunking
        return Chunk(data, size=got, allocation=allocation)
