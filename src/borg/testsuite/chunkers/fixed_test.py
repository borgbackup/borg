import pytest

from . import cf, make_sparsefile, make_content, fs_supports_sparse
from . import BS, map_sparse1, map_sparse2, map_onlysparse, map_notsparse
from ...chunkers import ChunkerFixed
from ...constants import *  # NOQA


@pytest.mark.skipif(not fs_supports_sparse(), reason="fs does not support sparse files")
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
        chunker = ChunkerFixed(4096, header_size=header_size, sparse=sparse)
        with open(fname, "rb") as fd:
            return cf(chunker.chunkify(fd))

    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map, header_size=header_size)
    get_chunks(fn, sparse=sparse, header_size=header_size) == make_content(sparse_map, header_size=header_size)
