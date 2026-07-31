# cython: language_level=3

import os
import cython
import time

from cpython.bytes cimport PyBytes_AsString
from libc.stdint cimport uint8_t, uint64_t, int64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcpy, memmove, memset

from ..crypto.low_level import CSPRNG

from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros
from .reader import FileReader, Chunk

# toeplitz-aes: a "Chk-PHTE" style chunker (UHF-then-PRF, like rabin-aes and
# goldilocks-aes - see rabin_aes.pyx for the full motivation) whose UHF is a
# tabulated LFSR-based Toeplitz hash (Krawczyk, CRYPTO '94 - "LFSR-based
# hashing and authentication"):
#
#   1. the rolling *universal hash* over the 64-byte window is
#          digest = sum_j x^(63-j) * T[b_j]   over GF(2)[x] mod P,
#      where T is a secret random table of 256 uint64 values (2 KiB of key
#      material) and P is a FIXED PUBLIC irreducible polynomial of degree 64
#      (x^64 + x^4 + x^3 + x + 1, the x^64 bit implicit; the same polynomial
#      CLHASH uses for GF(2^64)). Two distinct windows collide with
#      probability EXACTLY 2^-64 over the choice of T: their difference is
#      sum_v c_v * T[v] with at least one coefficient c_v a nonzero
#      polynomial of degree < 64 - which mod an irreducible degree-64 P is an
#      invertible field element, making the sum uniform. This bound is
#      unconditional (P is public; no irreducibility sampling at setup) and
#      optimal for a 64-bit digest - better than rabin-aes (~2^-55) and
#      goldilocks-aes (~2^-58).
#      NOTE the window must be exactly 64 bytes: the argument needs distinct
#      powers x^0..x^63 of degree < 64 per position. (A plain-rotation
#      variant - keyed buzhash - fails here: rotations satisfy R^64 = I, so
#      e.g. two all-same-byte windows collide with probability 1/2.)
#   2. a *PRF* (AES-128 with a secret key) is applied to the digest; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(digest) & mask) == 0.
#
# Performance: same batching structure as rabin-aes (two even/odd rolling
# lanes, grouped AES). The rolling step is d' = d*x ^ x^64*T[out] ^ T[in],
# where d*x mod P is a shift plus a branchless masked XOR - and both table
# lookups are indexed by *plaintext* bytes. The serial dependency chain thus
# contains no memory loads at all (rabin-aes has a digest-indexed reduction
# lookup in its chain), which also means no secret-dependent memory access
# in the hot loop (cache-side-channel posture like goldilocks-aes).

cdef extern from "toeplitz_aes_impl.h":
    ctypedef struct TP_CTX:
        pass
    int TP_TABLES
    TP_CTX *tp_new(const uint64_t *tables, const uint8_t *aes_key, int force_sw)
    void tp_free(TP_CTX *ctx)
    const char *tp_kind(const TP_CTX *ctx)
    uint64_t tp_digest64(const TP_CTX *ctx, const uint8_t *q)
    int64_t tp_scan(TP_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)


# --- GF(2)[x] helpers (pure Python, used at chunker setup only) ----------

# the fixed public irreducible polynomial P = x^64 + x^4 + x^3 + x + 1
_P = (1 << 64) | 0x1B
_WINDOW_SIZE = 64  # bytes; hard requirement of the collision bound, see above


def _poly_mod(v):
    """v mod P in GF(2)[x]."""
    while v.bit_length() - 1 >= 64:
        v ^= _P << (v.bit_length() - 1 - 64)
    return v


def _build_tables(t):
    """Build the rolling tables for T (order must match TP_TABLES in the C kernel).

    in0_tbl[b]   = T[b]                (incoming byte, newest position)
    in1_tbl[b]   = (x    * T[b]) mod P (stride-2, older incoming byte)
    out64_tbl[b] = (x^64 * T[b]) mod P (removal of the byte leaving the window)
    out65_tbl[b] = (x^65 * T[b]) mod P (stride-2 removal, older leaving byte)

    Tables 1..3 are algebraic combinations of T and P; they let the C kernel
    run two independent even/odd rolling lanes (see toeplitz_aes_impl.c)
    without changing any cut point.
    """
    in0_tbl = list(t)
    in1_tbl = [_poly_mod(v << 1) for v in t]
    out64_tbl = [_poly_mod(v << 64) for v in t]
    out65_tbl = [_poly_mod(v << 65) for v in t]
    return in0_tbl, in1_tbl, out64_tbl, out65_tbl


def _derive(bytes key):
    """Derive (aes_key, T, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then the
    table T as one 2048-byte block, split into 256 little-endian uint64.
    T must be uniform (not e.g. bit-balanced): the 2^-64 collision bound
    needs independent uniform entries.
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    blob = rng.random_bytes(8 * 256)
    t = [int.from_bytes(blob[8 * i : 8 * i + 8], "little") for i in range(256)]
    tables = _build_tables(t)
    return aes_key, t, tables


cdef class ChunkerToeplitzAES:
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling tabulated Toeplitz hash (secret 2 KiB table, fixed public
    polynomial, 64-byte window) post-processed with AES-128; the cut decision
    only sees the AES output, so observed chunk boundaries do not leak usable
    information about the chunking secret (see module docstring).
    """
    cdef uint64_t chunk_mask
    cdef uint64_t mask_s, mask_l  # normalized chunking: strict / loose masks
    cdef size_t normal_size       # chunk length at which we switch mask_s -> mask_l
    cdef int nc_level             # normalized chunking level (0 = disabled)
    cdef TP_CTX* ctx
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
        cdef uint64_t c_tables[4 * 256]
        cdef int i, t
        self.ctx = NULL
        self.data = NULL
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        assert max_size <= len(zeros)
        assert min_size + 1 <= max_size, "too small max_size"
        # the rolling window needs 64 bytes of in-chunk history at the first
        # possible cut position (min_size), so the minimum chunk size must be
        # at least the window size:
        assert chunk_min_exp >= 6, "chunk_min_exp must be >= 6 (2^6 = 64 = window size)"

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

        aes_key, table, tables = _derive(key)
        assert len(tables) == TP_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]
        force_sw = os.environ.get("BORG_TOEPLITZ_AES_FORCE_EVP", "") not in ("", "0")
        self.ctx = tp_new(c_tables, aes_key, 1 if force_sw else 0)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up toeplitz-aes kernel")

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
        if self.ctx != NULL:
            tp_free(self.ctx)
            self.ctx = NULL
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'aes-arm64', 'aes-ni' or 'evp'."""
        return (<bytes>tp_kind(self.ctx)).decode("ascii")

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
        digest = tp_digest64(self.ctx, self.data + self.position - 64)

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
            r = tp_scan(self.ctx, p, span, &digest, mask)
            if r == -2:
                raise Exception("toeplitz-aes: OpenSSL EVP encryption failed")
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


def toeplitz_aes_get_table(bytes key):
    """Get the secret table T derived from <key> (for tests)."""
    aes_key, t, tables = _derive(key)
    return t


def toeplitz_aes_get_tables(bytes key):
    """Get the (in0, in1, out64, out65) rolling tables derived from <key> (for tests)."""
    aes_key, t, tables = _derive(key)
    return tables


def toeplitz_aes_digest64(bytes key, bytes window):
    """C-kernel digest of a 64-byte window for the table derived from <key> (for tests).

    Lets tests verify the kernel's GF(2)[x] mod P arithmetic against a
    pure-Python big-int reference.
    """
    cdef uint64_t c_tables[4 * 256]
    cdef uint8_t aes_key_c[16]
    cdef TP_CTX *ctx
    cdef uint64_t d
    cdef int i, t
    assert len(window) == _WINDOW_SIZE
    aes_key, tt, tables = _derive(key)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    memset(aes_key_c, 0, 16)
    ctx = tp_new(c_tables, aes_key_c, 1)
    if ctx == NULL:
        raise MemoryError("Failed to set up toeplitz-aes kernel")
    d = tp_digest64(ctx, <const uint8_t*>PyBytes_AsString(window))
    tp_free(ctx)
    return d
