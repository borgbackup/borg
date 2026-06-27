from hashlib import sha256
from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand
from ...chunkers import ChunkerFastCDC, get_chunker
from ...chunkers.fastcdc import fastcdc_get_gear_table
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_fastcdc_unchanged():
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
        for minexp in (4, 6, 7, 11, 12):
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (4, 7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerFastCDC(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("50d39b6f30214d78f665ff97a4800142cddcb6a7c5995e5d162f9c6dceb20cfe")


def test_fastcdc_chunksize_distribution():
    data = os.urandom(1048576)
    min_exp, max_exp, mask, nc_level = 10, 16, 14, 2  # chunk size target 16 KiB, clip at 1 KiB and 64 KiB
    chunker = ChunkerFastCDC(key0, min_exp, max_exp, mask, nc_level)
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
    # most chunks should be cut due to the gear hash triggering, not due to clipping at min/max size:
    assert min_count < 10
    assert max_count < 10


def test_fastcdc_gear_table():
    # Test that the function returns a list of 256 integers
    table0 = fastcdc_get_gear_table(key0)
    assert len(table0) == 256
    for value in table0:
        assert isinstance(value, int)
        assert 0 <= value < 2**64

    # deterministic (same key produces same table)
    assert table0 == fastcdc_get_gear_table(key0)

    # different keys produce different tables
    table1 = fastcdc_get_gear_table(key1)
    assert table0 != table1


def test_fastcdc_get_chunker():
    # without a key, get_chunker uses an all-zero key; chunking must still work and be deterministic
    data = os.urandom(2 * 1024 * 1024)
    a = cf_expand(get_chunker(*FASTCDC_PARAMS, key=None).chunkify(BytesIO(data)))
    b = cf_expand(get_chunker(*FASTCDC_PARAMS, key=None).chunkify(BytesIO(data)))
    assert a == b
    assert b"".join(a) == data


def test_fastcdc_params_parsing():
    from argparse import ArgumentTypeError

    from ...helpers import ChunkerParams

    # fastcdc, chunk_min, chunk_max, chunk_mask, nc_level (no window field)
    assert ChunkerParams("fastcdc,19,23,21,2") == (CH_FASTCDC, 19, 23, 21, 2)
    assert ChunkerParams("fastcdc,10,23,16,0") == (CH_FASTCDC, 10, 23, 16, 0)
    # a 6-field (buzhash64-style, with window) fastcdc must be rejected
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("fastcdc,19,23,21,4095,2")
    # nc_level out of range (chunk_mask - nc_level < 1)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("fastcdc,19,23,21,21")
    # chunk_min <= chunk_mask <= chunk_max violated
    with pytest.raises(ArgumentTypeError):
        ChunkerParams("fastcdc,19,23,24,2")


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz_fastcdc(worker):
    # Fuzz fastcdc with random and uniform data of misc. sizes and misc keys.
    def rnd_key():
        return os.urandom(32)

    # decompose FASTCDC_PARAMS = (algo, min_exp, max_exp, mask_bits, nc_level)
    algo, min_exp, max_exp, mask_bits, nc_level = FASTCDC_PARAMS
    assert algo == CH_FASTCDC

    keys = [b"\0" * 32] + [rnd_key() for _ in range(10)]
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for key in keys:
        chunker = ChunkerFastCDC(key, min_exp, max_exp, mask_bits, nc_level)
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
