# more hashindex tests. kept separate so we can use pytest here.

import os
import random

import pytest

from ..hashindex import NSIndex


def verify_hash_table(kv, idx):
    """kv should be a python dictionary and idx an NSIndex.  Check that idx
    has the expected entries and the right number of entries.
    """
    for k, v in kv.items():
        assert k in idx and idx[k] == (v, v, v)
    assert len(idx) == len(kv)


def make_hashtables(*, entries, loops):
    idx = NSIndex()
    kv = {}
    for i in range(loops):
        # put some entries
        for j in range(entries):
            k = random.randbytes(32)
            v = random.randint(0, NSIndex.MAX_VALUE - 1)
            idx[k] = (v, v, v)
            kv[k] = v
        # check and delete a random amount of entries
        delete_keys = random.sample(list(kv), k=random.randint(0, len(kv)))
        for k in delete_keys:
            v = kv.pop(k)
            assert idx.pop(k) == (v, v, v)
        verify_hash_table(kv, idx)
    return idx, kv


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
def test_hashindex_stress():
    """checks if the hashtable behaves as expected

    This can be used in _hashindex.c before running this test to provoke more collisions (don't forget to compile):
    #define HASH_MAX_LOAD .99
    #define HASH_MAX_EFF_LOAD .999
    """
    make_hashtables(entries=10000, loops=1000)  # we do quite some assertions while making them


def test_hashindex_compact():
    """test that we do not lose or corrupt data by the compaction nor by expanding/rebuilding"""
    idx, kv = make_hashtables(entries=5000, loops=5)
    size_noncompact = idx.size()
    # compact the hashtable (remove empty/tombstone buckets)
    saved_space = idx.compact()
    # did we actually compact (reduce space usage)?
    size_compact = idx.size()
    assert saved_space > 0
    assert size_noncompact - size_compact == saved_space
    # did we lose anything?
    verify_hash_table(kv, idx)
    # now expand the hashtable again. trigger a resize/rebuild by adding an entry.
    k = b"x" * 32
    idx[k] = (0, 0, 0)
    kv[k] = 0
    size_rebuilt = idx.size()
    assert size_rebuilt > size_compact + 1
    # did we lose anything?
    verify_hash_table(kv, idx)


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
def test_hashindex_compact_stress():
    for _ in range(100):
        test_hashindex_compact()
