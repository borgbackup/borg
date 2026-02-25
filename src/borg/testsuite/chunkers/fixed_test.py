from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand, make_sparsefile, make_content, fs_supports_sparse
from . import BS, map_sparse1, map_sparse2, map_onlysparse, map_notsparse
from ...chunkers import ChunkerFixed
from ...constants import *  # NOQA


@pytest.mark.skipif(not fs_supports_sparse(), reason="filesystem does not support sparse files")
@pytest.mark.parametrize(
    "fname, sparse_map, header_size, sparse",
    [
        ("sparse1", map_sparse1, 0, False),
        ("sparse1", map_sparse1, 0, True),
        ("sparse1", map_sparse1, BS, False),
        ("sparse1", map_sparse1, BS, True),
        ("sparse2", map_sparse2, 0, False),
        ("sparse2", map_sparse2, 0, True),
        ("sparse2", map_sparse2, BS, False),
        ("sparse2", map_sparse2, BS, True),
        ("onlysparse", map_onlysparse, 0, False),
        ("onlysparse", map_onlysparse, 0, True),
        ("onlysparse", map_onlysparse, BS, False),
        ("onlysparse", map_onlysparse, BS, True),
        ("notsparse", map_notsparse, 0, False),
        ("notsparse", map_notsparse, 0, True),
        ("notsparse", map_notsparse, BS, False),
        ("notsparse", map_notsparse, BS, True),
    ],
)
def test_chunkify_sparse(tmpdir, fname, sparse_map, header_size, sparse):
    def get_chunks(fname, sparse, header_size):
        chunker = ChunkerFixed(BS, header_size=header_size, sparse=sparse)
        with open(fname, "rb") as fd:
            return cf(chunker.chunkify(fd))

    # this only works if sparse map blocks are same size as fixed chunker blocks
    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map, header_size=header_size)
    expected_content = make_content(sparse_map, header_size=header_size)
    assert get_chunks(fn, sparse=sparse, header_size=header_size) == expected_content


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz_fixed(worker):
    # Fuzz fixed chunker with random and uniform data of misc. sizes.
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for block_size, header_size in [(1024, 64), (1234, 0), (4321, 123)]:
        chunker = ChunkerFixed(block_size, header_size)
        for size in sizes:
            # Random data
            data = os.urandom(size)
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data

            # All-same data (non-zero)
            data = b"\x42" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data

            # All-zero data
            data = b"\x00" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            reconstructed = b"".join(parts)
            assert reconstructed == data
