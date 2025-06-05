import os
import tempfile

from borg.constants import *  # noqa

from ...chunkers import has_seek_hole


def cf(chunks):
    """chunk filter"""

    # this is to simplify testing: either return the data piece (bytes) or the hole length (int).
    def _cf(chunk):
        if chunk.meta["allocation"] == CH_DATA:
            assert len(chunk.data) == chunk.meta["size"]
            return bytes(chunk.data)  # make sure we have bytes, not memoryview
        if chunk.meta["allocation"] in (CH_HOLE, CH_ALLOC):
            assert chunk.data is None
            return chunk.meta["size"]
        assert False, "unexpected allocation value"

    return [_cf(chunk) for chunk in chunks]


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
