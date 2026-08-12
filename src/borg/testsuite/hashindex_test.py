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
    assert chunks.is_pending(x)
    pending = ChunkIndex.F_USED | ChunkIndex.F_PENDING  # add() sets F_PENDING alongside F_USED
    assert chunks[x] == ChunkIndexEntry(
        flags=pending, size=0, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
    )
    chunks.add(x, 2)  # updating size (we do not have a size yet)
    assert chunks[x] == ChunkIndexEntry(
        flags=pending, size=2, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
    )
    chunks.add(x, 2)
    assert chunks[x] == ChunkIndexEntry(
        flags=pending, size=2, pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
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
    assert chunks.is_pending(x1)
    assert chunks.is_pending(x2)

    pack_id = H2(3)
    # Both chunks land in the same pack: batch update in one call.
    chunks.update_pack_info([(x1, pack_id, 0, 50), (x2, pack_id, 50, 60)])
    # resolving the location clears the pending flag
    assert not chunks.is_pending(x1)
    assert not chunks.is_pending(x2)
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


def _cie(key):
    return ChunkIndexEntry(flags=ChunkIndex.F_USED, size=1, pack_id=key, obj_offset=0, obj_size=0)


def test_new_count():
    chunks = ChunkIndex()
    assert chunks.new_count == 0
    keys = [H2(x) for x in range(10)]
    for i, key in enumerate(keys):
        chunks[key] = _cie(key)
        assert chunks.new_count == i + 1
    chunks[keys[0]] = _cie(keys[0])  # overwriting a new entry: it stays new, not counted twice
    assert chunks.new_count == 10
    del chunks[keys[9]]  # deleting a new entry decrements
    assert chunks.new_count == 9
    chunks.clear_new()
    assert chunks.new_count == 0
    chunks[keys[9]] = _cie(keys[9])  # re-inserting: new again
    assert chunks.new_count == 1
    chunks[keys[0]] = _cie(keys[0])  # overwriting a not-new entry: it stays not-new
    assert chunks.new_count == 1
    del chunks[keys[0]]  # deleting a not-new entry: no change
    assert chunks.new_count == 1
    with pytest.raises(struct.error):  # a failing insert must not bump the count
        chunks[H2(11)] = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=2**33, pack_id=H2(11), obj_offset=0, obj_size=0)
    assert chunks.new_count == 1
    chunks.clear()
    assert chunks.new_count == 0


def test_new_count_after_read(tmp_path):
    # .write() persists the raw entries including the F_NEW flag, so a freshly loaded
    # ChunkIndex must compute new_count (lazily) from the loaded entries.
    chunks = ChunkIndex()
    keys = [H2(x) for x in range(5)]
    for key in keys:
        chunks[key] = _cie(key)
    chunks.clear_new()
    new_key = H2(1000)
    chunks[new_key] = _cie(new_key)
    path = str(tmp_path / "chunks")
    chunks.write(path)
    loaded = ChunkIndex.read(path)
    assert loaded.new_count == 1
    loaded.clear_new()
    assert loaded.new_count == 0


def test_iteritems_prefix():
    prefix_bits = 3
    chunks = ChunkIndex()
    keys = [H2(x) for x in range(100)]
    for key in keys:
        chunks[key] = _cie(key)
    collected = []
    for prefix in range(2**prefix_bits):
        part = [key for key, _ in chunks.iteritems(prefix_bits=prefix_bits, prefix=prefix)]
        assert all(key[0] >> (8 - prefix_bits) == prefix for key in part)
        collected += part
    assert sorted(collected) == sorted(keys)  # complete and disjoint
    # combining a prefix filter with only_new:
    chunks.clear_new()
    new_key = H2(1000)
    chunks[new_key] = _cie(new_key)
    new_prefix = new_key[0] >> (8 - prefix_bits)
    for prefix in range(2**prefix_bits):
        part = [key for key, _ in chunks.iteritems(only_new=True, prefix_bits=prefix_bits, prefix=prefix)]
        assert part == ([new_key] if prefix == new_prefix else [])
