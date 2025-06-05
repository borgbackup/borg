# cython: language_level=3

API_VERSION = '1.2_01'

import cython
import time
from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint32_t
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
# (1) the hash is designed for inputs <= 32 bytes, but the chunker uses it on a 4095 byte window;
#     any repeating bytes at distance 32 within those 4095 bytes can cause cancellation within
#     the hash function, e.g. in "X <any 31 bytes> X", the last X would cancel out the influence
#     of the first X on the hash value.
#
# (2) the hash table is supposed to have (according to the BUZ) exactly a 50% distribution of
#     0/1 bit values per position, but the hard coded table below doesn't fit that property.
#
# (3) if you would use a window size divisible by 64, the seed would cancel itself out completely.
#     this is why we use a window size of 4095 bytes.
#
# Another quirk is that, even with the 4095 byte window, XORing the entire table by a constant
# is equivalent to XORing the hash output with a different constant. but since the seed is stored
# encrypted, i think it still serves its purpose.

cdef uint32_t table_base[256]
table_base = [
    0xe7f831ec, 0xf4026465, 0xafb50cae, 0x6d553c7a, 0xd639efe3, 0x19a7b895, 0x9aba5b21, 0x5417d6d4,
    0x35fd2b84, 0xd1f6a159, 0x3f8e323f, 0xb419551c, 0xf444cebf, 0x21dc3b80, 0xde8d1e36, 0x84a32436,
    0xbeb35a9d, 0xa36f24aa, 0xa4e60186, 0x98d18ffe, 0x3f042f9e, 0xdb228bcd, 0x096474b7, 0x5c20c2f7,
    0xf9eec872, 0xe8625275, 0xb9d38f80, 0xd48eb716, 0x22a950b4, 0x3cbaaeaa, 0xc37cddd3, 0x8fea6f6a,
    0x1d55d526, 0x7fd6d3b3, 0xdaa072ee, 0x4345ac40, 0xa077c642, 0x8f2bd45b, 0x28509110, 0x55557613,
    0xffc17311, 0xd961ffef, 0xe532c287, 0xaab95937, 0x46d38365, 0xb065c703, 0xf2d91d0f, 0x92cd4bb0,
    0x4007c712, 0xf35509dd, 0x505b2f69, 0x557ead81, 0x310f4563, 0xbddc5be8, 0x9760f38c, 0x701e0205,
    0x00157244, 0x14912826, 0xdc4ca32b, 0x67b196de, 0x5db292e8, 0x8c1b406b, 0x01f34075, 0xfa2520f7,
    0x73bc37ab, 0x1e18bc30, 0xfe2c6cb3, 0x20c522d0, 0x5639e3db, 0x942bda35, 0x899af9d1, 0xced44035,
    0x98cc025b, 0x255f5771, 0x70fefa24, 0xe928fa4d, 0x2c030405, 0xb9325590, 0x20cb63bd, 0xa166305d,
    0x80e52c0a, 0xa8fafe2f, 0x1ad13f7d, 0xcfaf3685, 0x6c83a199, 0x7d26718a, 0xde5dfcd9, 0x79cf7355,
    0x8979d7fb, 0xebf8c55e, 0xebe408e4, 0xcd2affba, 0xe483be6e, 0xe239d6de, 0x5dc1e9e0, 0x0473931f,
    0x851b097c, 0xac5db249, 0x09c0f9f2, 0xd8d2f134, 0xe6f38e41, 0xb1c71bf1, 0x52b6e4db, 0x07224424,
    0x6cf73e85, 0x4f25d89c, 0x782a7d74, 0x10a68dcd, 0x3a868189, 0xd570d2dc, 0x69630745, 0x9542ed86,
    0x331cd6b2, 0xa84b5b28, 0x07879c9d, 0x38372f64, 0x7185db11, 0x25ba7c83, 0x01061523, 0xe6792f9f,
    0xe5df07d1, 0x4321b47f, 0x7d2469d8, 0x1a3a4f90, 0x48be29a3, 0x669071af, 0x8ec8dd31, 0x0810bfbf,
    0x813a06b4, 0x68538345, 0x65865ddc, 0x43a71b8e, 0x78619a56, 0x5a34451d, 0x5bdaa3ed, 0x71edc7e9,
    0x17ac9a20, 0x78d10bfa, 0x6c1e7f35, 0xd51839d9, 0x240cbc51, 0x33513cc1, 0xd2b4f795, 0xccaa8186,
    0x0babe682, 0xa33cf164, 0x18c643ea, 0xc1ca105f, 0x9959147a, 0x6d3d94de, 0x0b654fbe, 0xed902ca0,
    0x7d835cb5, 0x99ba1509, 0x6445c922, 0x495e76c2, 0xf07194bc, 0xa1631d7e, 0x677076a5, 0x89fffe35,
    0x1a49bcf3, 0x8e6c948a, 0x0144c917, 0x8d93aea1, 0x16f87ddf, 0xc8f25d49, 0x1fb11297, 0x27e750cd,
    0x2f422da1, 0xdee89a77, 0x1534c643, 0x457b7b8b, 0xaf172f7a, 0x6b9b09d6, 0x33573f7f, 0xf14e15c4,
    0x526467d5, 0xaf488241, 0x87c3ee0d, 0x33be490c, 0x95aa6e52, 0x43ec242e, 0xd77de99b, 0xd018334f,
    0x5b78d407, 0x498eb66b, 0xb1279fa8, 0xb38b0ea6, 0x90718376, 0xe325dee2, 0x8e2f2cba, 0xcaa5bdec,
    0x9d652c56, 0xad68f5cb, 0xa77591af, 0x88e37ee8, 0xf8faa221, 0xfcbbbe47, 0x4f407786, 0xaf393889,
    0xf444a1d9, 0x15ae1a2f, 0x40aa7097, 0x6f9486ac, 0x29d232a3, 0xe47609e9, 0xe8b631ff, 0xba8565f4,
    0x11288749, 0x46c9a838, 0xeb1b7cd8, 0xf516bbb1, 0xfb74fda0, 0x010996e6, 0x4c994653, 0x1d889512,
    0x53dcd9a3, 0xdd074697, 0x1e78e17c, 0x637c98bf, 0x930bb219, 0xcf7f75b0, 0xcb9355fb, 0x9e623009,
    0xe466d82c, 0x28f968d3, 0xfeb385d9, 0x238e026c, 0xb8ed0560, 0x0c6a027a, 0x3d6fec4b, 0xbb4b2ec2,
    0xe715031c, 0xeded011d, 0xcdc4d3b9, 0xc456fc96, 0xdd0eea20, 0xb3df8ec9, 0x12351993, 0xd9cbb01c,
    0x603147a2, 0xcf37d17d, 0xf7fcd9dc, 0xd8556fa3, 0x104c8131, 0x13152774, 0xb4715811, 0x6a72c2c9,
    0xc5ae37bb, 0xa76ce12a, 0x8150d8f3, 0x2ec29218, 0xa35f0984, 0x48c0647e, 0x0b5ff98c, 0x71893f7b
]

# This seems to be the most reliable way to inline this code, using a C preprocessor macro:
cdef extern from *:
   """
   #define BARREL_SHIFT(v, shift) (((v) << (shift)) | ((v) >> (((32 - (shift)) & 0x1f))))
   """
   uint32_t BARREL_SHIFT(uint32_t v, uint32_t shift)


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
cdef uint32_t* buzhash_init_table(uint32_t seed):
    """Initialize the buzhash table with the given seed."""
    cdef int i
    cdef uint32_t* table = <uint32_t*>malloc(1024)  # 256 * sizeof(uint32_t)
    for i in range(256):
        table[i] = table_base[i] ^ seed
    return table


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint32_t _buzhash(const unsigned char* data, size_t len, const uint32_t* h):
    """Calculate the buzhash of the given data."""
    cdef uint32_t i
    cdef uint32_t sum = 0, imod
    for i in range(len - 1, 0, -1):
        imod = i & 0x1f
        sum ^= BARREL_SHIFT(h[data[0]], imod)
        data += 1
    return sum ^ h[data[0]]


@cython.boundscheck(False)  # Deactivate bounds checking
@cython.wraparound(False)  # Deactivate negative indexing.
@cython.cdivision(True)  # Use C division/modulo semantics for integer division.
cdef uint32_t _buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, const uint32_t* h):
    """Update the buzhash with a new byte."""
    cdef uint32_t lenmod = len & 0x1f
    return BARREL_SHIFT(sum, 1) ^ BARREL_SHIFT(h[remove], lenmod) ^ h[add]


cdef class Chunker:
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
    cdef uint32_t chunk_mask
    cdef uint32_t* table
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

    def __cinit__(self, int seed, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int hash_window_size, bint sparse=False):
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        # see chunker_process, first while loop condition, first term must be able to get True:
        assert hash_window_size + min_size + 1 <= max_size, "too small max_size"

        self.window_size = hash_window_size
        self.chunk_mask = (1 << hash_mask_bits) - 1
        self.min_size = min_size
        self.table = buzhash_init_table(seed & 0xffffffff)
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
        cdef uint32_t sum, chunk_mask = self.chunk_mask
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
        sum = _buzhash(self.data + self.position, window_size, self.table)

        while self.remaining > self.window_size and (sum & chunk_mask) and not (self.eof and self.remaining <= window_size):
            p = self.data + self.position
            stop_at = p + self.remaining - window_size

            while p < stop_at and (sum & chunk_mask):
                sum = _buzhash_update(sum, p[0], p[window_size], window_size, self.table)
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


def buzhash(data, unsigned long seed):
    cdef uint32_t *table
    cdef uint32_t sum
    table = buzhash_init_table(seed & 0xffffffff)
    sum = _buzhash(<const unsigned char *> data, len(data), table)
    free(table)
    return sum


def buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, unsigned long seed):
    cdef uint32_t *table
    table = buzhash_init_table(seed & 0xffffffff)
    sum = _buzhash_update(sum, remove, add, len, table)
    free(table)
    return sum
