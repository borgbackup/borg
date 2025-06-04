from hashlib import sha256
from io import BytesIO
import os

from . import cf
from ...chunkers import Chunker
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


def H(data):
    return sha256(data).digest()


def test_chunkpoints_unchanged():
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
                    for seed in (1849058162, 1234567653):
                        fh = BytesIO(data)
                        chunker = Chunker(seed, minexp, maxexp, maskbits, winsize)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimisations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    assert overall_hash == hex_to_bin("a43d0ecb3ae24f38852fcc433a83dacd28fe0748d09cc73fc11b69cf3f1a7299")


def test_buzhash_chunksize_distribution():
    data = os.urandom(1048576)
    min_exp, max_exp, mask = 10, 16, 14  # chunk size target 16kiB, clip at 1kiB and 64kiB
    chunker = Chunker(0, min_exp, max_exp, mask, 4095)
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
