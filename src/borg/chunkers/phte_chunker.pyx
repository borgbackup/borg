# cython: language_level=3

import time

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memmove, memset

from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros
from .reader import FileReader, Chunk

# Shared chunker driver for the "UHF-then-PRF" (Chk-PHTE) chunkers: rabin-aes,
# goldilocks-aes and toeplitz-aes. They differ only in their rolling universal
# hash, which lives in their C kernels (see phte_core.h / phte_scan.h) and in
# the key derivation in their own modules. Everything else - buffering,
# min/max clamping, normalized chunking, the scan loop, sparse/hole handling -
# is identical and implemented here once.
#
# Subclasses implement _scan() and _digest64() by calling their C kernel. Both
# are Cython cdef methods, i.e. one vtable-dispatched call per *scan span*
# (up to a whole chunk of data) and per chunk start - never per byte, so the
# indirection is not measurable.


cdef class ChunkerPHTE:
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
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        assert min_size + 1 <= max_size, "too small max_size"
        # the rolling window needs 64 bytes of in-chunk history at the first
        # possible cut position (min_size), so the minimum chunk size must be
        # at least the window size:
        assert chunk_min_exp >= 6, "chunk_min_exp must be >= 6 (2^6 = 64 = window size)"

        self.algo = algo
        self.kernel_str = "unknown"
        self.chunk_mask = (1ULL << hash_mask_bits) - 1
        self.min_size = min_size
        # Normalized chunking, identical structure to the fastcdc chunker (see there);
        # the AES output is uniform, so contiguous low-bit masks are fine.
        assert nc_level >= 0
        assert hash_mask_bits - nc_level >= 1, "nc_level too large for hash_mask_bits"
        assert hash_mask_bits + nc_level <= 48, "nc_level too large for hash_mask_bits"
        self.nc_level = nc_level
        if nc_level:
            self.mask_s = (1ULL << (hash_mask_bits + nc_level)) - 1
            self.mask_l = (1ULL << (hash_mask_bits - nc_level)) - 1
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
        """Scan n positions, see the kernel's <prefix>scan(). Implemented by subclasses."""
        return -1

    cdef uint64_t _digest64(self, const uint8_t *q) noexcept:
        """Digest of the 64 bytes at q (window warm-up). Implemented by subclasses."""
        return 0

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'aes-arm64', 'aes-ni' or 'evp'."""
        return self.kernel_str

    cdef int fill(self) except 0:
        """Fill the chunker's buffer with more data."""
        cdef ssize_t n

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

        # skip the sub-minimum region (no cut allowed below min_size), then scan.
        # warm up the rolling digest over the 64 bytes preceding the first
        # scan position (they are within the current chunk, since min_size >= 64).
        self.position += min_size
        self.remaining -= min_size
        digest = self._digest64(self.data + self.position - 64)

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
        if zeros.startswith(data):
            data = None
            allocation = CH_ALLOC
        else:
            allocation = CH_DATA
        self.chunking_time += time.monotonic() - started_chunking
        return Chunk(data, size=got, allocation=allocation)
