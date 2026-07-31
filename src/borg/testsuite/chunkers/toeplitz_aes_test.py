from hashlib import sha256
from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand
from ...chunkers import ChunkerToeplitzAES, get_chunker
from ...chunkers.rabin_aes import _is_irreducible
from ...chunkers.toeplitz_aes import toeplitz_aes_digest64, toeplitz_aes_get_table, toeplitz_aes_get_tables, _P
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_toeplitz_aes_unchanged():
    def twist(size):
        x = 1
        a = bytearray(size)
        for i in range(size):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            a[i] = x & 0xFF
        return a

    data = twist(100000)

    runs = []
    for nc_level in (0, 2, 3):
        for minexp in (6, 7, 11, 12):  # toeplitz-aes requires minexp >= 6 (64-byte window)
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerToeplitzAES(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("d98a97b3eeb1122c602c4581f486bd356404447efe2bf550000e12d1f046b843")


def test_toeplitz_aes_kernels_identical():
    # the OpenSSL EVP batch path and the AES hardware instruction path (if available
    # on this platform) must produce identical cut points.
    data = os.urandom(4 * 1024 * 1024)

    def sizes(chunker):
        return [c.meta["size"] for c in chunker.chunkify(BytesIO(data))]

    default = ChunkerToeplitzAES(key0, 10, 16, 14, 2)
    sizes_default = sizes(default)
    os.environ["BORG_TOEPLITZ_AES_FORCE_EVP"] = "1"
    try:
        forced = ChunkerToeplitzAES(key0, 10, 16, 14, 2)
        assert forced.kernel == "evp"
        sizes_evp = sizes(forced)
    finally:
        del os.environ["BORG_TOEPLITZ_AES_FORCE_EVP"]
    assert sizes_default == sizes_evp
    # whatever kernel was selected by default, it must be a known one
    assert default.kernel in ("aes-arm64", "aes-ni", "evp")


def test_toeplitz_aes_chunksize_distribution():
    data = os.urandom(1048576)
    min_exp, max_exp, mask, nc_level = 10, 16, 14, 2  # chunk size target 16 KiB, clip at 1 KiB and 64 KiB
    chunker = ChunkerToeplitzAES(key0, min_exp, max_exp, mask, nc_level)
    f = BytesIO(data)
    chunks = cf(chunker.chunkify(f))
    del chunks[-1]  # get rid of the last chunk, it can be smaller than 2**min_exp
    chunk_sizes = [len(chunk) for chunk in chunks]
    chunks_count = len(chunks)
    min_chunksize_observed = min(chunk_sizes)
    max_chunksize_observed = max(chunk_sizes)
    min_count = sum(int(size == 2**min_exp) for size in chunk_sizes)
    max_count = sum(int(size == 2**max_exp) for size in chunk_sizes)
    print(
        f"count: {chunks_count} min: {min_chunksize_observed} max: {max_chunksize_observed} "
        f"min count: {min_count} max count: {max_count}"
    )
    # usually there will about 64 chunks
    assert 32 < chunks_count < 128
    # chunks always must be between min and max (clipping must work):
    assert min_chunksize_observed >= 2**min_exp
    assert max_chunksize_observed <= 2**max_exp
    # most chunks should be cut due to the hash triggering, not due to clipping at min/max size:
    assert min_count < 10
    assert max_count < 10


def test_toeplitz_aes_shift_resilience():
    # content-defined cuts must survive a prefix insertion (this also validates that the
    # rolling digest update and the per-chunk window warm-up agree with each other).
    data = os.urandom(4 * 1024 * 1024)

    def chunk_hashes(data):
        chunker = ChunkerToeplitzAES(key0, 10, 16, 14, 2)
        return [H(c) for c in cf_expand(chunker.chunkify(BytesIO(data)))]

    h1 = set(chunk_hashes(data))
    h2 = chunk_hashes(b"PREFIX_SHIFTS_EVERYTHING" + data)
    survived = sum(1 for h in h2 if h in h1)
    assert survived / len(h2) > 0.9


def test_toeplitz_aes_polynomial_and_tables():
    # the fixed public polynomial must be irreducible of degree 64
    # (reuse the rabin-aes Rabin test, which handles degree 64)
    assert _P.bit_length() - 1 == 64
    assert _is_irreducible(_P)

    # T must be deterministically derived from the key
    t0 = toeplitz_aes_get_table(key0)
    assert len(t0) == 256
    assert all(0 <= v < 2**64 for v in t0)
    assert t0 == toeplitz_aes_get_table(key0)
    t1 = toeplitz_aes_get_table(key1)
    assert t0 != t1

    def pmod(v):
        while v.bit_length() - 1 >= 64:
            v ^= _P << (v.bit_length() - 1 - 64)
        return v

    in0_tbl, in1_tbl, out64_tbl, out65_tbl = toeplitz_aes_get_tables(key0)
    assert in0_tbl == t0
    assert len(in1_tbl) == len(out64_tbl) == len(out65_tbl) == 256
    # spot check the derived tables against T and P
    for b in (0, 1, 2, 128, 255):
        assert in1_tbl[b] == pmod(t0[b] << 1)
        assert out64_tbl[b] == pmod(t0[b] << 64)
        assert out65_tbl[b] == pmod(t0[b] << 65)


def test_toeplitz_aes_digest_reference():
    # the C kernel's digest must match a pure-Python big-int reference:
    # digest = sum_j x^(63-j) * T[b_j] mod P
    def pmod(v):
        while v.bit_length() - 1 >= 64:
            v ^= _P << (v.bit_length() - 1 - 64)
        return v

    rng = random.Random(42)
    for key in (key0, key1):
        t = toeplitz_aes_get_table(key)
        windows = [b"\x00" * 64, b"\xff" * 64, b"\x42" * 64, bytes(range(64))]
        windows += [rng.randbytes(64) for _ in range(10)]
        for w in windows:
            ref = 0
            for b in w:
                ref = pmod(ref << 1) ^ t[b]
            assert toeplitz_aes_digest64(key, w) == ref


def test_toeplitz_aes_get_chunker():
    # without a key, get_chunker uses an all-zero key; chunking must still work and be deterministic
    data = os.urandom(2 * 1024 * 1024)
    a = cf_expand(get_chunker(*TOEPLITZ_AES_PARAMS, key=None).chunkify(BytesIO(data)))
    b = cf_expand(get_chunker("toeplitz-aes", 19, 23, 21, 2, key=None).chunkify(BytesIO(data)))
    assert a == b
    assert b"".join(a) == data


def test_toeplitz_aes_params_parsing():
    from argparse import ArgumentTypeError

    from ...helpers import ChunkerParams

    # toeplitz-aes, chunk_min, chunk_max, chunk_mask, nc_level (no window field)
    assert ChunkerParams("toeplitz-aes,19,23,21,2") == (CH_TOEPLITZ_AES, 19, 23, 21, 2)
    assert ChunkerParams("toeplitz-aes,10,23,16,0") == (CH_TOEPLITZ_AES, 10, 23, 16, 0)
    # a 6-field (buzhash64-style, with window) toeplitz-aes must be rejected
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("toeplitz-aes,19,23,21,4095,2")
    # a 4-field toeplitz-aes (missing nc_level) must be rejected, not fall into old-style compat mode
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("toeplitz-aes,19,23,21")
    # nc_level out of range (chunk_mask - nc_level < 1)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("toeplitz-aes,19,23,21,21")
    # chunk_min <= chunk_mask <= chunk_max violated
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("toeplitz-aes,19,23,24,2")
    # chunk_min < 6 is not allowed (the 64-byte window needs 64 bytes of in-chunk history)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("toeplitz-aes,5,23,21,2")


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz_toeplitz_aes(worker):
    # Fuzz toeplitz-aes with random and uniform data of misc. sizes and misc keys.
    def rnd_key():
        return os.urandom(32)

    # decompose TOEPLITZ_AES_PARAMS = (algo, min_exp, max_exp, mask_bits, nc_level)
    algo, min_exp, max_exp, mask_bits, nc_level = TOEPLITZ_AES_PARAMS
    assert algo == CH_TOEPLITZ_AES

    keys = [b"\0" * 32] + [rnd_key() for _ in range(10)]
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for key in keys:
        chunker = ChunkerToeplitzAES(key, min_exp, max_exp, mask_bits, nc_level)
        for size in sizes:
            # Random data
            data = os.urandom(size)
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data

            # All-same data (non-zero)
            data = b"\x42" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data

            # All-zero data
            data = b"\x00" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data
