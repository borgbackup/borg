import os
import random

import pytest

from ..hashindex import NSIndex


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
def test_hashindex_stress():
    """checks if the hashtable behaves as expected"""
    ENTRIES = 10000
    LOOPS = 100
    idx = NSIndex()
    kv = {}
    for i in range(LOOPS):
        # put some entries
        for j in range(ENTRIES):
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
