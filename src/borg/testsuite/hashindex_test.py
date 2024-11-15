import hashlib
import struct

import pytest

from ..hashindex import ChunkIndex, ChunkIndexEntry


def H(x):
    # make some 32byte long thing that depends on x
    return bytes("%-0.32d" % x, "ascii")


def H2(x):
    # like H(x), but with pseudo-random distribution of the output value
    return hashlib.sha256(H(x)).digest()


def test_chunkindex_add():
    chunks = ChunkIndex()
    x = H2(1)
    chunks.add(x, 0)
    assert chunks[x] == ChunkIndexEntry(flags=ChunkIndex.F_USED, size=0)
    chunks.add(x, 2)  # updating size (we do not have a size yet)
    assert chunks[x] == ChunkIndexEntry(flags=ChunkIndex.F_USED, size=2)
    chunks.add(x, 2)
    assert chunks[x] == ChunkIndexEntry(flags=ChunkIndex.F_USED, size=2)
    with pytest.raises(AssertionError):
        chunks.add(x, 3)  # inconsistent size (we already have a different size)


def test_keyerror():
    chunks = ChunkIndex()
    x = H2(1)
    with pytest.raises(KeyError):
        chunks[x]
    with pytest.raises(struct.error):
        chunks[x] = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=2**33)


def test_new():
    def new_chunks():
        return list(chunks.iteritems(only_new=True))

    chunks = ChunkIndex()
    key1, value1a = H2(1), ChunkIndexEntry(flags=ChunkIndex.F_USED, size=23)
    key2, value2a = H2(2), ChunkIndexEntry(flags=ChunkIndex.F_USED, size=42)
    # tracking of new entries
    assert new_chunks() == []
    chunks[key1] = value1a
    assert new_chunks() == [(key1, value1a)]
    chunks.clear_new()
    assert new_chunks() == []
    chunks[key2] = value2a
    assert new_chunks() == [(key2, value2a)]
    chunks.clear_new()
    assert new_chunks() == []
