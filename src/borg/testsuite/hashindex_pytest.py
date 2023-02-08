# more hashindex tests. kept separate so we can use pytest here.

import os
import random

import pytest

from ..hashindex import NSIndex


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
        # check if remaining entries are as expected
        for k, v in kv.items():
            assert idx[k] == (v, v, v)
        # check entry count
        assert len(kv) == len(idx)
    return idx, kv


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
def test_hashindex_stress():
    """checks if the hashtable behaves as expected

    This can be used in _hashindex.c before running this test to provoke more collisions (don't forget to compile):
    #define HASH_MAX_LOAD .99
    #define HASH_MAX_EFF_LOAD .999
    """
    make_hashtables(entries=10000, loops=1000)  # we do quite some assertions while making them
