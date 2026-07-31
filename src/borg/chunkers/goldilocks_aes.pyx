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

# goldilocks-aes: the reference "Chk-PHTE" construction of eprint 2025/558
# ("Breaking and Fixing Content-Defined Chunking"; Truong, Merz, Scarlata,
# Guenther, Paterson), implemented borg-style for comparison with rabin-aes.
#
# Same UHF-then-PRF split as rabin-aes (see rabin_aes.pyx for the full
# motivation); only the UHF differs:
#
#   1. the rolling *universal hash* is a polynomial hash over the prime field
#      GF(p) with p = 2^64 - 2^32 + 1 (the "Goldilocks" prime, chosen for its
#      cheap 2^64 = 2^32 - 1 reduction) at a secret random evaluation point K:
#      over the 64-byte window, state = sum b_j * K^(63-j) mod p (oldest byte
#      at K^63, newest at K^0). This is the UHF the paper's own reference
#      implementation uses (their Rust prf-chunker, via the risc0 Goldilocks
#      field). Two distinct windows collide with probability <= 63/p ~= 2^-58
#      over the choice of K (the difference is a nonzero polynomial in K of
#      degree <= 63) - a slightly *better* bound than rabin-aes's <= 511/2^63,
#      because the polynomial is over bytes, not bits.
#   2. a *PRF* (AES-128 with a secret key) is applied to the state; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(state) & mask) == 0.
#
# The kernel keeps all field values canonical (< p), so the AES input is a
# unique function of the window and all code paths cut identically.
#
# Performance: same batching structure as rabin-aes (the state stream is
# independent of where cuts happen), same two-lane rolling and grouped AES;
# the difference under test is purely GF(p) multiply-based rolling versus
# GF(2)[x] table-based rolling.

cdef extern from "goldilocks_aes_impl.h":
    ctypedef struct GL_CTX:
        pass
    int GL_TABLES
    GL_CTX *gl_new(const uint64_t *tables, uint64_t k1, uint64_t k2, const uint8_t *aes_key, int force_sw)
    void gl_free(GL_CTX *ctx)
    const char *gl_kind(const GL_CTX *ctx)
    uint64_t gl_digest64(const GL_CTX *ctx, const uint8_t *q)
    int64_t gl_scan(GL_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)


# --- Goldilocks field helpers (pure Python, used at chunker setup only) ---

_GL_P = 0xFFFFFFFF00000001  # the Goldilocks prime 2^64 - 2^32 + 1
_WINDOW_SIZE = 64  # bytes


def _sample_key_elem(rng):
    """Sample the secret evaluation point K uniformly from GF(p) (rejection).

    Uniformity over the whole field is exactly what the collision bound needs;
    a candidate is rejected with probability ~2^-32, so this almost always
    accepts the first sample.
    """
    while True:
        v = int.from_bytes(rng.random_bytes(8), "little")
        if v < _GL_P:
            return v


def _build_tables(k):
    """Build the rolling tables for K (order must match GL_TABLES in the C kernel).

    nout64_tbl[b] = (-b * K^64) mod p  (removal of the byte leaving the window)
    nout65_tbl[b] = (-b * K^65) mod p  (stride-2 removal, older leaving byte)
    in1_tbl[b]    = ( b * K   ) mod p  (stride-2, older incoming byte)

    The removal tables are negated so the C kernel's per-byte delta is a pure
    sum; the stride-2 tables are algebraic combinations of the single-step
    update and let the kernel run two independent even/odd rolling lanes (see
    goldilocks_aes_impl.c) without changing any cut point.
    """
    k64 = pow(k, _WINDOW_SIZE, _GL_P)
    k65 = (k64 * k) % _GL_P
    nout64_tbl = [(-b * k64) % _GL_P for b in range(256)]
    nout65_tbl = [(-b * k65) % _GL_P for b in range(256)]
    in1_tbl = [(b * k) % _GL_P for b in range(256)]
    return nout64_tbl, nout65_tbl, in1_tbl


def _derive(bytes key):
    """Derive (aes_key, K, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then K
    (8 bytes per candidate until accepted).
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    k = _sample_key_elem(rng)
    tables = _build_tables(k)
    return aes_key, k, tables


cdef class ChunkerGoldilocksAES:
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling polynomial hash over the Goldilocks prime field (secret evaluation
    point, 64-byte window) post-processed with AES-128; the cut decision only
    sees the AES output, so observed chunk boundaries do not leak usable
    information about the chunking secret (see module docstring).
    """
    cdef uint64_t chunk_mask
    cdef uint64_t mask_s, mask_l  # normalized chunking: strict / loose masks
    cdef size_t normal_size       # chunk length at which we switch mask_s -> mask_l
    cdef int nc_level             # normalized chunking level (0 = disabled)
    cdef GL_CTX* ctx
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
        cdef uint64_t c_tables[3 * 256]
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

        aes_key, k, tables = _derive(key)
        assert len(tables) == GL_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]
        force_sw = os.environ.get("BORG_GOLDILOCKS_AES_FORCE_EVP", "") not in ("", "0")
        self.ctx = gl_new(c_tables, k, (k * k) % _GL_P, aes_key, 1 if force_sw else 0)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up goldilocks-aes kernel")

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
            gl_free(self.ctx)
            self.ctx = NULL
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'aes-arm64', 'aes-ni' or 'evp'."""
        return (<bytes>gl_kind(self.ctx)).decode("ascii")

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
        # warm up the rolling state over the 64 bytes preceding the first
        # scan position (they are within the current chunk, since min_size >= 64).
        self.position += min_size
        self.remaining -= min_size
        digest = gl_digest64(self.ctx, self.data + self.position - 64)

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
            r = gl_scan(self.ctx, p, span, &digest, mask)
            if r == -2:
                raise Exception("goldilocks-aes: OpenSSL EVP encryption failed")
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


def goldilocks_aes_get_key_elem(bytes key):
    """Get the secret evaluation point K derived from <key> (for tests)."""
    aes_key, k, tables = _derive(key)
    return k


def goldilocks_aes_get_tables(bytes key):
    """Get the (nout64, nout65, in1) rolling tables derived from <key> (for tests)."""
    aes_key, k, tables = _derive(key)
    return tables


def goldilocks_aes_digest64(k, bytes window):
    """C-kernel Horner digest of a 64-byte window for evaluation point k (for tests).

    Lets tests verify the kernel's GF(p) arithmetic (gl_mul/gl_add) against a
    pure-Python big-int reference, including values close to p.
    """
    cdef uint64_t c_tables[3 * 256]
    cdef uint8_t aes_key[16]
    cdef GL_CTX *ctx
    cdef uint64_t d
    cdef int i, t
    assert len(window) == _WINDOW_SIZE
    assert 0 <= k < _GL_P
    tables = _build_tables(k)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    memset(aes_key, 0, 16)
    ctx = gl_new(c_tables, k, (k * k) % _GL_P, aes_key, 1)
    if ctx == NULL:
        raise MemoryError("Failed to set up goldilocks-aes kernel")
    d = gl_digest64(ctx, <const uint8_t*>PyBytes_AsString(window))
    gl_free(ctx)
    return d


def goldilocks_aes_scan_all(k, bytes aes_key, bytes data, mask, bint force_sw=False):
    """Raw kernel scan over all window positions >= 64 (for tests).

    Returns the list of positions i where the cut condition matches, i.e.
    (AES(state of window data[i-63..i]) & mask) == 0 - independent of any
    chunk min/max framing. force_sw selects the portable EVP path.
    """
    cdef uint64_t c_tables[3 * 256]
    cdef GL_CTX *ctx
    cdef const uint8_t *base
    cdef uint64_t digest, c_mask = mask
    cdef size_t pos, n
    cdef int64_t r
    cdef int i, t
    assert 0 <= k < _GL_P
    assert len(aes_key) == 16
    assert len(data) > _WINDOW_SIZE
    tables = _build_tables(k)
    for t in range(len(tables)):
        for i in range(256):
            c_tables[t * 256 + i] = tables[t][i]
    ctx = gl_new(c_tables, k, (k * k) % _GL_P, <const uint8_t*>PyBytes_AsString(aes_key), 1 if force_sw else 0)
    if ctx == NULL:
        raise MemoryError("Failed to set up goldilocks-aes kernel")
    try:
        base = <const uint8_t*>PyBytes_AsString(data)
        n = len(data)
        digest = gl_digest64(ctx, base)  # state at position 63
        pos = _WINDOW_SIZE
        result = []
        while pos < n:
            r = gl_scan(ctx, base + pos, n - pos, &digest, c_mask)
            if r == -2:
                raise Exception("goldilocks-aes: OpenSSL EVP encryption failed")
            if r < 0:
                break
            result.append(pos + <size_t>r)
            pos += <size_t>r + 1
        return result
    finally:
        gl_free(ctx)
