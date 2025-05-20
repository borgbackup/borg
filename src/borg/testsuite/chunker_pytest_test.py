from io import BytesIO
import os
import tempfile

import pytest

from .chunker_test import cf
from ..chunker import Chunker, ChunkerFixed, sparsemap, has_seek_hole, ChunkerFailing
from ..constants import *  # NOQA

BS = 4096  # fs block size

# some sparse files. X = content blocks, _ = sparse blocks.
# X__XXX____
map_sparse1 = [(0 * BS, 1 * BS, True), (1 * BS, 2 * BS, False), (3 * BS, 3 * BS, True), (6 * BS, 4 * BS, False)]

# _XX___XXXX
map_sparse2 = [(0 * BS, 1 * BS, False), (1 * BS, 2 * BS, True), (3 * BS, 3 * BS, False), (6 * BS, 4 * BS, True)]

# XXX
map_notsparse = [(0 * BS, 3 * BS, True)]

# ___
map_onlysparse = [(0 * BS, 3 * BS, False)]


def make_sparsefile(fname, sparsemap, header_size=0):
    with open(fname, "wb") as fd:
        total = 0
        if header_size:
            fd.write(b"H" * header_size)
            total += header_size
        for offset, size, is_data in sparsemap:
            if is_data:
                fd.write(b"X" * size)
            else:
                fd.seek(size, os.SEEK_CUR)
            total += size
        fd.truncate(total)
    assert os.path.getsize(fname) == total


def make_content(sparsemap, header_size=0):
    result = []
    total = 0
    if header_size:
        result.append(b"H" * header_size)
        total += header_size
    for offset, size, is_data in sparsemap:
        if is_data:
            result.append(b"X" * size)  # bytes!
        else:
            result.append(size)  # int!
        total += size
    return result


def fs_supports_sparse():
    if not has_seek_hole:
        return False
    with tempfile.TemporaryDirectory() as tmpdir:
        fn = os.path.join(tmpdir, "test_sparse")
        make_sparsefile(fn, [(0, BS, False), (BS, BS, True)])
        with open(fn, "rb") as f:
            try:
                offset_hole = f.seek(0, os.SEEK_HOLE)
                offset_data = f.seek(0, os.SEEK_DATA)
            except OSError:
                # no sparse support if these seeks do not work
                return False
        return offset_hole == 0 and offset_data == BS


@pytest.mark.skipif(not fs_supports_sparse(), reason="fs does not support sparse files")
@pytest.mark.parametrize(
    "fname, sparse_map",
    [("sparse1", map_sparse1), ("sparse2", map_sparse2), ("onlysparse", map_onlysparse), ("notsparse", map_notsparse)],
)
def test_sparsemap(tmpdir, fname, sparse_map):
    def get_sparsemap_fh(fname):
        fh = os.open(fname, flags=os.O_RDONLY)
        try:
            return list(sparsemap(fh=fh))
        finally:
            os.close(fh)

    def get_sparsemap_fd(fname):
        with open(fname, "rb") as fd:
            return list(sparsemap(fd=fd))

    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map)
    assert get_sparsemap_fh(fn) == sparse_map
    assert get_sparsemap_fd(fn) == sparse_map


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


def test_chunker_failing():
    SIZE = 4096
    data = bytes(2 * SIZE + 1000)
    chunker = ChunkerFailing(SIZE, "rEErrr")  # cut <SIZE> chunks, start failing at block 1, fail 2 times
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        c1 = next(ch)  # block 0: ok
        assert c1.meta["allocation"] == CH_DATA
        assert c1.data == data[:SIZE]
        with pytest.raises(OSError):  # block 1: failure 1
            next(ch)
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        with pytest.raises(OSError):  # block 2: failure 2
            next(ch)
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        c1 = next(ch)  # block 3: success!
        c2 = next(ch)  # block 4: success!
        c3 = next(ch)  # block 5: success!
        assert c1.meta["allocation"] == c2.meta["allocation"] == c3.meta["allocation"] == CH_DATA
        assert c1.data == data[:SIZE]
        assert c2.data == data[SIZE : 2 * SIZE]
        assert c3.data == data[2 * SIZE :]


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
