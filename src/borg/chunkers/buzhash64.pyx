# cython: language_level=3

API_VERSION = '1.2_01'

import cython
import time
from hashlib import sha256

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memmove

from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros
from .reader import FileReader, Chunk

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
   uint64_t BARREL_SHIFT64(uint64_t v, uint64_t shift)


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
cdef uint64_t* buzhash64_init_table(bytes key):
    """Initialize the buzhash table using the given key."""
    cdef int i
    cdef uint64_t* table = <uint64_t*>malloc(2048)  # 256 * sizeof(uint64_t)
    for i in range(256):
        # deterministically generate a pseudo-random 64-bit unsigned integer for table entry i involving the key:
        v = f"{i:02x}".encode() + key
        d64 = sha256(v).digest()[:8]
        table[i] = <uint64_t> int.from_bytes(d64, byteorder='little')
    return table


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint64_t _buzhash64(const unsigned char* data, size_t len, const uint64_t* h):
    """Calculate the buzhash of the given data."""
    cdef uint64_t i
    cdef uint64_t sum = 0, imod
    for i in range(len - 1, 0, -1):
        imod = i & 0x3f
        sum ^= BARREL_SHIFT64(h[data[0]], imod)
        data += 1
    return sum ^ h[data[0]]


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint64_t _buzhash64_update(uint64_t sum, unsigned char remove, unsigned char add, size_t len, const uint64_t* h):
    """Update the buzhash with a new byte."""
    cdef uint64_t lenmod = len & 0x3f
    return BARREL_SHIFT64(sum, 1) ^ BARREL_SHIFT64(h[remove], lenmod) ^ h[add]


cdef class ChunkerBuzHash64:
    """
    Content-Defined Chunker, variable chunk sizes.

    This chunker makes quite some effort to cut mostly chunks of the same-content, even if
    the content moves to a different offset inside the file. It uses the buzhash
    rolling-hash algorithm to identify the chunk cutting places by looking at the
    content inside the moving window and computing the rolling hash value over the
    window contents. If the last n bits of the rolling hash are 0, a chunk is cut.
    Additionally it obeys some more criteria, like a minimum and maximum chunk size.
    It also uses a per-repo random seed to avoid some chunk length fingerprinting attacks.
    """
    cdef uint64_t chunk_mask
    cdef uint64_t* table
    cdef uint8_t* data
    cdef object _fd  # Python object for file descriptor
    cdef int fh
    cdef int done, eof
    cdef size_t min_size, buf_size, window_size, remaining, position, last
    cdef long long bytes_read, bytes_yielded  # off_t in C, using long long for compatibility
    cdef readonly float chunking_time
    cdef object file_reader  # FileReader instance
    cdef size_t reader_block_size
    cdef bint sparse

    def __cinit__(self, bytes key, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int hash_window_size, bint sparse=False):
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        # see chunker_process, first while loop condition, first term must be able to get True:
        assert hash_window_size + min_size + 1 <= max_size, "too small max_size"

        self.window_size = hash_window_size
        self.chunk_mask = (1 << hash_mask_bits) - 1
        self.min_size = min_size
        self.table = buzhash64_init_table(key)
        self.buf_size = max_size
        self.data = <uint8_t*>malloc(self.buf_size)
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
        """Free the chunker's resources."""
        if self.table != NULL:
            free(self.table)
            self.table = NULL
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    cdef int fill(self) except 0:
        """Fill the chunker's buffer with more data."""
        cdef ssize_t n
        cdef object chunk

        # Move remaining data to the beginning of the buffer
        memmove(self.data, self.data + self.last, self.position + self.remaining - self.last)
        self.position -= self.last
        self.last = 0
        n = self.buf_size - self.position - self.remaining

        if self.eof or n == 0:
            return 1

        # Use FileReader to read data
        chunk = self.file_reader.read(n)
        n = chunk.meta["size"]

        if n > 0:
            # Only copy data if it's not a hole
            if chunk.meta["allocation"] == CH_DATA:
                # Copy data from chunk to our buffer
                memcpy(self.data + self.position + self.remaining, <const unsigned char*>PyBytes_AsString(chunk.data), n)
            else:
                # For holes, fill with zeros
                memcpy(self.data + self.position + self.remaining, <const unsigned char*>PyBytes_AsString(zeros[:n]), n)

            self.remaining += n
            self.bytes_read += n
        else:
            self.eof = 1

        return 1

    cdef object process(self) except *:
        """Process the chunker's buffer and return the next chunk."""
        cdef uint64_t sum, chunk_mask = self.chunk_mask
        cdef size_t n, old_last, min_size = self.min_size, window_size = self.window_size
        cdef uint8_t* p
        cdef uint8_t* stop_at
        cdef size_t did_bytes

        if self.done:
            if self.bytes_read == self.bytes_yielded:
                raise StopIteration
            else:
                raise Exception("chunkifier byte count mismatch")

        while self.remaining < min_size + window_size + 1 and not self.eof:  # see assert in Chunker init
            if not self.fill():
                return None

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
        sum = _buzhash64(self.data + self.position, window_size, self.table)

        while self.remaining > self.window_size and (sum & chunk_mask) and not (self.eof and self.remaining <= window_size):
            p = self.data + self.position
            stop_at = p + self.remaining - window_size

            while p < stop_at and (sum & chunk_mask):
                sum = _buzhash64_update(sum, p[0], p[window_size], window_size, self.table)
                p += 1

            did_bytes = p - (self.data + self.position)
            self.position += did_bytes
            self.remaining -= did_bytes

            if self.remaining <= window_size:
                if not self.fill():
                    return None

        if self.remaining <= window_size:
            self.position += self.remaining
            self.remaining = 0

        old_last = self.last
        self.last = self.position
        n = self.last - old_last
        self.bytes_yielded += n

        # Return a memory view of the chunk
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
        # we do not have SEEK_DATA/SEEK_HOLE support in chunker_process C code,
        # but we can just check if data was all-zero (and either came from a hole
        # or from stored zeros - we can not detect that here).
        if zeros.startswith(data):
            data = None
            allocation = CH_ALLOC
        else:
            allocation = CH_DATA
        self.chunking_time += time.monotonic() - started_chunking
        return Chunk(data, size=got, allocation=allocation)


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
