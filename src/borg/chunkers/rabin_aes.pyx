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

# rabin-aes: a "Chk-PHTE" style content-defined chunker (UHF-then-PRF).
#
# Motivated by "Breaking and Fixing Content-Defined Chunking" (Truong, Merz,
# Scarlata, Guenther, Paterson; eprint 2025/558) and Alexeev/Percival/Zhang
# (arXiv 2504.02095): keyed chunkers built by hiding a secret inside a rolling
# hash (secret buzhash/gear tables) admit key-recovery attacks from known
# plaintext, because every observed cut is an equation about the secret.
# The provably sound construction separates the two jobs:
#
#   1. a rolling *universal hash function* (UHF) compresses the last w bytes
#      into a short digest; here: a Rabin fingerprint over GF(2)[x]/P(x) with
#      a secret random irreducible polynomial P of degree 63, over a 64-byte
#      window (the same UHF family restic uses, with a bigger polynomial).
#   2. a *PRF* (AES-128 with a secret key) is applied to the digest; the cut
#      decision looks only at the PRF output (low bits of the first 8
#      ciphertext bytes, little-endian): cut iff (AES(digest) & mask) == 0.
#
# An attacker who observes cut positions sees only PRF outputs; the digest and
# P remain hidden behind AES. Two windows colliding under the UHF is the only
# residual leakage (they necessarily get equal decisions); for a degree-63
# random irreducible P the collision probability of two distinct 64-byte
# windows is <= 511/2^62 ~= 2^-53.
#
# Security notes (honest limits):
#  * The FSWC-RoR proof bound (eprint 2025/558, Thm 4.5 analogue) degrades
#    with the square of the number of processed positions; with a 63-bit
#    digest it stays meaningful up to roughly tens of GiB per chunker key.
#    Beyond that, no *attack* is known - but the guarantee is heuristic, like
#    everything else in this area except a wider-digest construction.
#  * As with any deterministic chunker, equal chunks still produce equal
#    lengths (deduplication requires this); see the paper's discussion.
#
# Performance: the digest stream is independent of where cuts happen (each
# digest is a pure function of the last 64 bytes), so digests can be computed
# ahead and encrypted in batches. The C kernel (rabin_aes_impl.c) does this
# either via OpenSSL EVP AES-128-ECB batches (portable) or, where available,
# via AES instructions (arm64 crypto extension / x86-64 AES-NI) interleaved
# with the rolling-hash chain. All paths produce bit-identical cuts.

cdef extern from "rabin_aes_impl.h":
    ctypedef struct RA_CTX:
        pass
    int RA_TABLES
    RA_CTX *ra_new(const uint64_t *tables, const uint8_t *aes_key, int force_sw)
    void ra_free(RA_CTX *ctx)
    const char *ra_kind(const RA_CTX *ctx)
    uint64_t ra_digest64(const RA_CTX *ctx, const uint8_t *q)
    int64_t ra_scan(RA_CTX *ctx, const uint8_t *p, size_t n, uint64_t *digest, uint64_t mask)


# --- GF(2)[x] polynomial helpers (pure Python, used at chunker setup only) ---

_DEG = 63  # degree of the secret irreducible polynomial P
_WINDOW_SIZE = 64  # bytes; window polynomial degree is 8 * 64 - 1 = 511

# spread table for GF(2) squaring: 8 bits -> 16 bits with zeros interleaved
_SPREAD8 = []
for _b in range(256):
    _s = 0
    for _i in range(8):
        if _b & (1 << _i):
            _s |= 1 << (2 * _i)
    _SPREAD8.append(_s)


def _poly_mod(v, p):
    """v mod p in GF(2)[x]; p must have its top bit set at degree deg(p)."""
    dp = p.bit_length() - 1
    while v.bit_length() - 1 >= dp:
        v ^= p << (v.bit_length() - 1 - dp)
    return v


def _poly_sq_mod(a, p):
    """a^2 mod p in GF(2)[x] (square = interleave zeros between bits)."""
    sq = 0
    shift = 0
    while a:
        sq |= _SPREAD8[a & 0xFF] << shift
        a >>= 8
        shift += 16
    return _poly_mod(sq, p)


def _poly_gcd(a, b):
    """gcd(a, b) in GF(2)[x]."""
    while b:
        a, b = b, _poly_mod(a, b)
    return a


def _is_irreducible(p):
    """Rabin's irreducibility test for deg(p) == 63 (prime factors of 63: 3, 7).

    p is irreducible iff x^(2^63) == x (mod p) and gcd(x^(2^(63/q)) - x, p) == 1
    for q in {3, 7}, i.e. for the exponents 21 and 9.
    """
    assert p.bit_length() - 1 == _DEG
    x = 2  # the polynomial "x"
    r = x
    saved = {}
    for i in range(1, _DEG + 1):
        r = _poly_sq_mod(r, p)
        if i in (9, 21):
            saved[i] = r
    if r != x:
        return False
    for e in (21, 9):
        if _poly_gcd(p, saved[e] ^ x) != 1:
            return False
    return True


def _sample_polynomial(rng):
    """Sample a random irreducible polynomial of degree 63 from the CSPRNG.

    The polynomial has its degree-63 and constant coefficients set; the 62
    middle coefficients are random. About 1 in 63 candidates is irreducible.
    """
    while True:
        v = int.from_bytes(rng.random_bytes(8), "little")
        p = (1 << _DEG) | (v & ((1 << _DEG) - 1)) | 1
        if _is_irreducible(p):
            return p


def _build_tables(p):
    """Build the rolling tables for P (order must match RA_TABLES in the C kernel).

    out_tbl[b]   = poly(b) * x^504 mod P  (remove the byte leaving the window;
                                           504 = 8 * (window_size - 1))
    red_tbl[t]   = poly(t) * x^63 mod P   (reduce the 8 bits shifted above bit 62)
    w1_tbl[t]    = poly(t) * x^71 mod P   (stride-2 step: reduce bits 71..78)
    out8_tbl[b]  = poly(b) * x^512 mod P  (stride-2 removal, newer byte)
    out16_tbl[b] = poly(b) * x^520 mod P  (stride-2 removal, older byte)

    The last three are algebraic combinations of the first two; they let the C
    kernel run two independent even/odd rolling lanes (see rabin_aes_impl.c)
    without changing any cut point.
    """
    out_tbl = [_poly_mod(b << (8 * (_WINDOW_SIZE - 1)), p) for b in range(256)]
    red_tbl = [_poly_mod(t << _DEG, p) for t in range(256)]
    w1_tbl = [_poly_mod(t << (_DEG + 8), p) for t in range(256)]
    out8_tbl = [_poly_mod(b << (8 * _WINDOW_SIZE), p) for b in range(256)]
    out16_tbl = [_poly_mod(b << (8 * (_WINDOW_SIZE + 1)), p) for b in range(256)]
    return out_tbl, red_tbl, w1_tbl, out8_tbl, out16_tbl


def _derive(bytes key):
    """Derive (aes_key, P, tables) deterministically from a 256-bit key.

    Frozen derivation order (changing it changes all cut points and thus breaks
    deduplication against existing repos): first the 16-byte AES key, then P
    (8 bytes per candidate until irreducible).
    """
    rng = CSPRNG(key)
    aes_key = rng.random_bytes(16)
    p = _sample_polynomial(rng)
    tables = _build_tables(p)
    return aes_key, p, tables


cdef class ChunkerRabinAES:
    """
    Content-Defined Chunker, variable chunk sizes, UHF-then-PRF cut decision.

    Rolling Rabin fingerprint (secret irreducible polynomial, 64-byte window)
    post-processed with AES-128; the cut decision only sees the AES output,
    so observed chunk boundaries do not leak usable information about the
    chunking secret (see module docstring).
    """
    cdef uint64_t chunk_mask
    cdef uint64_t mask_s, mask_l  # normalized chunking: strict / loose masks
    cdef size_t normal_size       # chunk length at which we switch mask_s -> mask_l
    cdef int nc_level             # normalized chunking level (0 = disabled)
    cdef RA_CTX* ctx
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
        cdef uint64_t c_tables[5 * 256]
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

        aes_key, p, tables = _derive(key)
        assert len(tables) == RA_TABLES
        for t in range(len(tables)):
            for i in range(256):
                c_tables[t * 256 + i] = tables[t][i]
        force_sw = os.environ.get("BORG_RABIN_AES_FORCE_EVP", "") not in ("", "0")
        self.ctx = ra_new(c_tables, aes_key, 1 if force_sw else 0)
        if self.ctx == NULL:
            raise MemoryError("Failed to set up rabin-aes kernel")

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
            ra_free(self.ctx)
            self.ctx = NULL
        if self.data != NULL:
            free(self.data)
            self.data = NULL

    @property
    def kernel(self):
        """Which scan kernel this chunker uses: 'aes-arm64', 'aes-ni' or 'evp'."""
        return (<bytes>ra_kind(self.ctx)).decode("ascii")

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
        digest = ra_digest64(self.ctx, self.data + self.position - 64)

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
            r = ra_scan(self.ctx, p, span, &digest, mask)
            if r == -2:
                raise Exception("rabin-aes: OpenSSL EVP encryption failed")
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


def rabin_aes_get_polynomial(bytes key):
    """Get the secret irreducible polynomial P derived from <key> (for tests)."""
    aes_key, p, tables = _derive(key)
    return p


def rabin_aes_get_tables(bytes key):
    """Get the (out_tbl, red_tbl) rolling tables derived from <key> (for tests)."""
    aes_key, p, tables = _derive(key)
    return tables[0], tables[1]
