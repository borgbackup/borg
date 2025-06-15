from hashlib import sha256
from io import BytesIO
import os

from . import cf
from ...chunkers import ChunkerBuzHash64
from ...chunkers.buzhash64 import buzhash64_get_table
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints64_unchanged():
    def twist(size):
        x = 1
        a = bytearray(size)
        for i in range(size):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            a[i] = x & 0xFF
        return a

    data = twist(100000)

    runs = []
    for winsize in (65, 129, HASH_WINDOW_SIZE, 7351):
        for minexp in (4, 6, 7, 11, 12):
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (4, 7, 10, 12):
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerBuzHash64(key, minexp, maxexp, maskbits, winsize)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimisations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("676676133fb3621ada0f6cc1b18002c3e37016c9469217d18f8e382fadaf23fd")


def test_buzhash64_chunksize_distribution():
    data = os.urandom(1048576)
    min_exp, max_exp, mask = 10, 16, 14  # chunk size target 16kiB, clip at 1kiB and 64kiB
    chunker = ChunkerBuzHash64(key0, min_exp, max_exp, mask, 4095)
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
    # most chunks should be cut due to buzhash triggering, not due to clipping at min/max size:
    assert min_count < 10
    assert max_count < 10


def test_buzhash64_table():
    # Test that the function returns a list of 256 integers
    table0 = buzhash64_get_table(key0)
    assert len(table0) == 256

    # Test that all elements are integers
    for value in table0:
        assert isinstance(value, int)

    # Test that the function is deterministic (same key produces same table)
    table0_again = buzhash64_get_table(key0)
    assert table0 == table0_again

    # Test that different keys produce different tables
    table1 = buzhash64_get_table(key1)
    assert table0 != table1

    # Test that the table has balanced bit distribution
    # For each bit position 0..63, exactly 50% of the table values should have the bit set to 1
    for bit_pos in range(64):
        bit_count = sum(1 for value in table0 if value & (1 << bit_pos))
        assert bit_count == 128  # 50% of 256 = 128
