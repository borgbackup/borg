from io import BytesIO
import os

import pytest

from ..chunker import ChunkerFixed, sparsemap
from ..constants import *  # NOQA

BS = 4096  # fs block size

# some sparse files. X = content blocks, _ = sparse blocks.
# X__XXX____
map_sparse1 = [
    (0 * BS, 1 * BS, True),
    (1 * BS, 2 * BS, False),
    (3 * BS, 3 * BS, True),
    (6 * BS, 4 * BS, False),
]

# _XX___XXXX
map_sparse2 = [
    (0 * BS, 1 * BS, False),
    (1 * BS, 2 * BS, True),
    (3 * BS, 3 * BS, False),
    (6 * BS, 4 * BS, True),
]

# XXX
map_notsparse = [(0 * BS, 3 * BS, True), ]

# ___
map_onlysparse = [(0 * BS, 3 * BS, False), ]


def make_sparsefile(fname, sparsemap, header_size=0):
    with open(fname, 'wb') as fd:
        total = 0
        if header_size:
            fd.write(b'H' * header_size)
            total += header_size
        for offset, size, is_data in sparsemap:
            if is_data:
                fd.write(b'X' * size)
            else:
                fd.seek(size, os.SEEK_CUR)
            total += size
        fd.truncate(total)
    assert os.path.getsize(fname) == total


def make_content(sparsemap, header_size=0):
    with BytesIO() as fd:
        total = 0
        if header_size:
            fd.write(b'H' * header_size)
            total += header_size
        for offset, size, is_data in sparsemap:
            if is_data:
                fd.write(b'X' * size)
            else:
                fd.write(b'\0' * size)
            total += size
        content = fd.getvalue()
    assert len(content) == total
    return content


@pytest.mark.parametrize("fname, sparse_map", [
    ('sparse1', map_sparse1),
    ('sparse2', map_sparse2),
    ('onlysparse', map_onlysparse),
    ('notsparse', map_notsparse),
])
def test_sparsemap(tmpdir, fname, sparse_map):

    def get_sparsemap_fh(fname):
        fh = os.open(fname, flags=os.O_RDONLY)
        try:
            return list(sparsemap(fh=fh))
        finally:
            os.close(fh)

    def get_sparsemap_fd(fname):
        with open(fname, 'rb') as fd:
            return list(sparsemap(fd=fd))

    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map)
    assert get_sparsemap_fh(fn) == sparse_map
    assert get_sparsemap_fd(fn) == sparse_map


@pytest.mark.parametrize("fname, sparse_map, header_size, sparse", [
    ('sparse1', map_sparse1, 0, False),
    ('sparse1', map_sparse1, 0, True),
    ('sparse1', map_sparse1, BS, False),
    ('sparse1', map_sparse1, BS, True),
    ('sparse2', map_sparse2, 0, False),
    ('sparse2', map_sparse2, 0, True),
    ('sparse2', map_sparse2, BS, False),
    ('sparse2', map_sparse2, BS, True),
    ('onlysparse', map_onlysparse, 0, False),
    ('onlysparse', map_onlysparse, 0, True),
    ('onlysparse', map_onlysparse, BS, False),
    ('onlysparse', map_onlysparse, BS, True),
    ('notsparse', map_notsparse, 0, False),
    ('notsparse', map_notsparse, 0, True),
    ('notsparse', map_notsparse, BS, False),
    ('notsparse', map_notsparse, BS, True),
])
def test_chunkify_sparse(tmpdir, fname, sparse_map, header_size, sparse):

    def get_chunks(fname, sparse, header_size):
        chunker = ChunkerFixed(4096, header_size=header_size, sparse=sparse)
        with open(fname, 'rb') as fd:
            return b''.join([c for c in chunker.chunkify(fd)])

    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map, header_size=header_size)
    get_chunks(fn, sparse=sparse, header_size=header_size) == make_content(sparse_map, header_size=header_size)
