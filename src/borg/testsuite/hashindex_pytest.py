import os
import random

import pytest

from borg.hashindex import NSIndex, ChunkIndex


def test_nsindex_iteritems_marker():
    nsindex = NSIndex()
    nsindex[b'\xbb'*32] = (123, 456)
    nsindex[b'\xaa'*32] = (234, 567)

    # marker exists
    items = list(nsindex.iteritems(marker=b'\xbb'*32))
    assert len(items) == 1
    assert items[0][0] == b'\xaa'*32

    # marker does not exist
    with pytest.raises(KeyError, match="marker not found"):
        list(nsindex.iteritems(marker=b'\xcc'*32))


def test_chunkindex_iteritems_marker():
    chunkindex = ChunkIndex()
    chunkindex[b'\xbb'*32] = (1, 100, 50)
    chunkindex[b'\xaa'*32] = (1, 200, 100)

    # marker exists
    items = list(chunkindex.iteritems(marker=b'\xbb'*32))
    assert len(items) == 1
    assert items[0][0] == b'\xaa'*32

    # marker does not exist
    with pytest.raises(KeyError, match="marker not found"):
        list(chunkindex.iteritems(marker=b'\xcc'*32))


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
def test_hashindex_stress():
    """Check if the hash table behaves as expected

    This can be used in _hashindex.c before running this test to provoke more collisions (don't forget to compile):
    #define HASH_MAX_LOAD .99
    #define HASH_MAX_EFF_LOAD .999
    """
    ENTRIES = 10000
    LOOPS = 1000
    idx = NSIndex()
    kv = {}
    for i in range(LOOPS):
        # Put some entries
        for j in range(ENTRIES):
            k = random.randbytes(32)
            v = random.randint(0, NSIndex.MAX_VALUE - 1)
            idx[k] = (v, v)
            kv[k] = v
        # Check and delete a random number of entries
        delete_keys = random.sample(list(kv), k=random.randint(0, len(kv)))
        for k in delete_keys:
            v = kv.pop(k)
            assert idx.pop(k) == (v, v)
        # Check whether the remaining entries are as expected
        for k, v in kv.items():
            assert idx[k] == (v, v)
        # Check entry count
        assert len(kv) == len(idx)
