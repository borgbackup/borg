import hashlib
import struct

import pytest

from ..constants import UNKNOWN_INT32, UNKNOWN_BYTES32
from ..hashindex import ChunkIndex, ChunkIndexEntry


def H(x):
    # Make a 32-byte value that depends on x
    return bytes("%-0.32d" % x, "ascii")


def H2(x):
    # Like H(x), but with a pseudo-random distribution of the output value
    return hashlib.sha256(H(x)).digest()


def test_chunkindex_add():
    chunks = ChunkIndex()
    x = H2(1)
    chunks.add(x, 0)
    assert chunks[x] == ChunkIndexEntry(
        flags=ChunkIndex.F_USED, size=0, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
    )
    chunks.add(x, 2)  # updating size (we do not have a size yet)
    assert chunks[x] == ChunkIndexEntry(
        flags=ChunkIndex.F_USED, size=2, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
    )
    chunks.add(x, 2)
    assert chunks[x] == ChunkIndexEntry(
        flags=ChunkIndex.F_USED, size=2, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
    )
    with pytest.raises(AssertionError):
        chunks.add(x, 3)  # inconsistent size (we already have a different size)


def test_chunkindex_update_pack_info():
    chunks = ChunkIndex()
    x1, x2 = H2(1), H2(2)
    chunks.add(x1, 10)
    chunks.add(x2, 20)
    assert chunks[x1].obj_offset == UNKNOWN_INT32
    assert chunks[x2].obj_offset == UNKNOWN_INT32

    pack_id = H2(3)
    # Both chunks land in the same pack: batch update in one call.
    chunks.update_pack_info([(x1, pack_id, 0, 50), (x2, pack_id, 50, 60)])
    # Location fields updated; flags and size must be unchanged.
    assert chunks[x1] == ChunkIndexEntry(flags=ChunkIndex.F_USED, size=10, pack_id=pack_id, obj_offset=0, obj_size=50)
    assert chunks[x2] == ChunkIndexEntry(flags=ChunkIndex.F_USED, size=20, pack_id=pack_id, obj_offset=50, obj_size=60)

    # None and empty list are both no-ops.
    chunks.update_pack_info(None)
    chunks.update_pack_info([])
    assert chunks[x1].obj_offset == 0


def test_keyerror():
    chunks = ChunkIndex()
    x = H2(1)
    with pytest.raises(KeyError):
        chunks[x]
    with pytest.raises(struct.error):
        chunks[x] = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=2**33, pack_id=x, obj_offset=0, obj_size=0)


def test_new():
    def new_chunks():
        return list(chunks.iteritems(only_new=True))

    chunks = ChunkIndex()
    key1 = H2(1)
    value1a = ChunkIndexEntry(flags=ChunkIndex.F_USED, size=23, pack_id=key1, obj_offset=0, obj_size=0)
    key2 = H2(2)
    value2a = ChunkIndexEntry(flags=ChunkIndex.F_USED, size=42, pack_id=key2, obj_offset=0, obj_size=0)
    # Tracking of new entries
    assert new_chunks() == []
    chunks[key1] = value1a
    assert new_chunks() == [(key1, value1a)]
    chunks.clear_new()
    assert new_chunks() == []
    chunks[key2] = value2a
    assert new_chunks() == [(key2, value2a)]
    chunks.clear_new()
    assert new_chunks() == []
