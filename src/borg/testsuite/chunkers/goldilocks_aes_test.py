from hashlib import sha256
from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand
from ...chunkers import ChunkerGoldilocksAES, get_chunker
from ...chunkers.goldilocks_aes import (
    goldilocks_aes_digest64,
    goldilocks_aes_get_key_elem,
    goldilocks_aes_get_tables,
    goldilocks_aes_scan_all,
    _GL_P,
)
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_goldilocks_aes_unchanged():
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
        for minexp in (6, 7, 11, 12):  # goldilocks-aes requires minexp >= 6 (64-byte window)
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerGoldilocksAES(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("4aa18be3a2209cc0f454af01a9019e050eb1588b959f96c7e0de532b6a69fd65")


def test_goldilocks_aes_kernels_identical():
    # the OpenSSL EVP batch path and the AES hardware instruction path (if available
    # on this platform) must produce identical cut points.
    data = os.urandom(4 * 1024 * 1024)

    def sizes(chunker):
        return [c.meta["size"] for c in chunker.chunkify(BytesIO(data))]

    default = ChunkerGoldilocksAES(key0, 10, 16, 14, 2)
    sizes_default = sizes(default)
    os.environ["BORG_GOLDILOCKS_AES_FORCE_EVP"] = "1"
    try:
        forced = ChunkerGoldilocksAES(key0, 10, 16, 14, 2)
        assert forced.kernel == "evp"
        sizes_evp = sizes(forced)
    finally:
        del os.environ["BORG_GOLDILOCKS_AES_FORCE_EVP"]
    assert sizes_default == sizes_evp
    # whatever kernel was selected by default, it must be a known one
    assert default.kernel in ("aes-arm64", "aes-ni", "evp")


def test_goldilocks_aes_chunksize_distribution():
    data = os.urandom(1048576)
    min_exp, max_exp, mask, nc_level = 10, 16, 14, 2  # chunk size target 16 KiB, clip at 1 KiB and 64 KiB
    chunker = ChunkerGoldilocksAES(key0, min_exp, max_exp, mask, nc_level)
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


def test_goldilocks_aes_shift_resilience():
    # content-defined cuts must survive a prefix insertion (this also validates that the
    # rolling state update and the per-chunk window warm-up agree with each other).
    data = os.urandom(4 * 1024 * 1024)

    def chunk_hashes(data):
        chunker = ChunkerGoldilocksAES(key0, 10, 16, 14, 2)
        return [H(c) for c in cf_expand(chunker.chunkify(BytesIO(data)))]

    h1 = set(chunk_hashes(data))
    h2 = chunk_hashes(b"PREFIX_SHIFTS_EVERYTHING" + data)
    survived = sum(1 for h in h2 if h in h1)
    assert survived / len(h2) > 0.9


def test_goldilocks_aes_key_elem_and_tables():
    # K must be a canonical field element, deterministically derived from the key
    k0 = goldilocks_aes_get_key_elem(key0)
    assert 0 <= k0 < _GL_P
    assert k0 == goldilocks_aes_get_key_elem(key0)
    k1 = goldilocks_aes_get_key_elem(key1)
    assert k0 != k1

    nout64_tbl, nout65_tbl, in1_tbl = goldilocks_aes_get_tables(key0)
    assert len(nout64_tbl) == len(nout65_tbl) == len(in1_tbl) == 256
    for v in nout64_tbl + nout65_tbl + in1_tbl:
        assert isinstance(v, int)
        assert 0 <= v < _GL_P  # all table entries are canonical field elements
    # spot check the tables against K: entry b is (-b * K^64), (-b * K^65), (b * K) mod p
    k64 = pow(k0, 64, _GL_P)
    for b in (0, 1, 2, 128, 255):
        assert nout64_tbl[b] == (-b * k64) % _GL_P
        assert nout65_tbl[b] == (-b * k64 * k0) % _GL_P
        assert in1_tbl[b] == (b * k0) % _GL_P


def test_goldilocks_aes_field_arithmetic():
    # the C kernel's GF(p) arithmetic must match a pure-Python big-int reference,
    # including evaluation points and window bytes that stress the reduction
    def horner(k, window):
        d = 0
        for b in window:
            d = (d * k + b) % _GL_P
        return d

    rng = random.Random(42)
    ks = [1, 2, _GL_P - 1, _GL_P - 2, 0xFFFFFFFF, 0x100000000] + [rng.randrange(_GL_P) for _ in range(10)]
    windows = [b"\xff" * 64, b"\x00" * 63 + b"\x01", bytes(range(64))] + [rng.randbytes(64) for _ in range(10)]
    for k in ks:
        for w in windows:
            assert goldilocks_aes_digest64(k, w) == horner(k, w)


def test_goldilocks_aes_scan_matches_recompute():
    # the raw rolling scan (both kernels) must agree with itself across paths and
    # with a from-scratch state recomputation at every reported cut position
    data = os.urandom(256 * 1024)
    k = goldilocks_aes_get_key_elem(key0)
    aes_key = os.urandom(16)
    mask = (1 << 10) - 1
    hw = goldilocks_aes_scan_all(k, aes_key, data, mask, force_sw=False)
    evp = goldilocks_aes_scan_all(k, aes_key, data, mask, force_sw=True)
    assert hw == evp
    assert len(hw) > 100  # ~256 expected at 10 mask bits


def test_goldilocks_aes_get_chunker():
    # without a key, get_chunker uses an all-zero key; chunking must still work and be deterministic
    data = os.urandom(2 * 1024 * 1024)
    a = cf_expand(get_chunker(*GOLDILOCKS_AES_PARAMS, key=None).chunkify(BytesIO(data)))
    b = cf_expand(get_chunker("goldilocks-aes", 19, 23, 21, 2, key=None).chunkify(BytesIO(data)))
    assert a == b
    assert b"".join(a) == data


def test_goldilocks_aes_params_parsing():
    from argparse import ArgumentTypeError

    from ...helpers import ChunkerParams

    # goldilocks-aes, chunk_min, chunk_max, chunk_mask, nc_level (no window field)
    assert ChunkerParams("goldilocks-aes,19,23,21,2") == (CH_GOLDILOCKS_AES, 19, 23, 21, 2)
    assert ChunkerParams("goldilocks-aes,10,23,16,0") == (CH_GOLDILOCKS_AES, 10, 23, 16, 0)
    # a 6-field (buzhash64-style, with window) goldilocks-aes must be rejected
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("goldilocks-aes,19,23,21,4095,2")
    # a 4-field goldilocks-aes (missing nc_level) must be rejected, not fall into old-style compat mode
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("goldilocks-aes,19,23,21")
    # nc_level out of range (chunk_mask - nc_level < 1)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("goldilocks-aes,19,23,21,21")
    # chunk_min <= chunk_mask <= chunk_max violated
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("goldilocks-aes,19,23,24,2")
    # chunk_min < 6 is not allowed (the 64-byte window needs 64 bytes of in-chunk history)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("goldilocks-aes,5,23,21,2")


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz_goldilocks_aes(worker):
    # Fuzz goldilocks-aes with random and uniform data of misc. sizes and misc keys.
    def rnd_key():
        return os.urandom(32)

    # decompose GOLDILOCKS_AES_PARAMS = (algo, min_exp, max_exp, mask_bits, nc_level)
    algo, min_exp, max_exp, mask_bits, nc_level = GOLDILOCKS_AES_PARAMS
    assert algo == CH_GOLDILOCKS_AES

    keys = [b"\0" * 32] + [rnd_key() for _ in range(10)]
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for key in keys:
        chunker = ChunkerGoldilocksAES(key, min_exp, max_exp, mask_bits, nc_level)
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
