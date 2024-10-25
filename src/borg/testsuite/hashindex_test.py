# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

import hashlib
import struct

from ..hashindex import ChunkIndex
from . import BaseTestCase


def H(x):
    # make some 32byte long thing that depends on x
    return bytes("%-0.32d" % x, "ascii")


def H2(x):
    # like H(x), but with pseudo-random distribution of the output value
    return hashlib.sha256(H(x)).digest()


class HashIndexRefcountingTestCase(BaseTestCase):
    def test_chunkindex_add(self):
        chunks = ChunkIndex()
        x = H2(1)
        chunks.add(x, 5, 6)
        assert chunks[x] == (5, 6)
        chunks.add(x, 1, 2)
        assert chunks[x] == (6, 2)

    def test_keyerror(self):
        chunks = ChunkIndex()
        x = H2(1)
        with self.assert_raises(KeyError):
            chunks[x]
        with self.assert_raises(struct.error):
            chunks.add(x, -1, 0)
