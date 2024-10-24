# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

import hashlib
import struct

from ..hashindex import NSIndex, ChunkIndex
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
        with self.assert_raises(KeyError):
            chunks[H(1)]
        with self.assert_raises(struct.error):
            chunks.add(H(1), -1, 0)


class IndexCorruptionTestCase(BaseTestCase):
    def test_bug_4829(self):
        from struct import pack

        def HH(x, y, z):
            # make some 32byte long thing that depends on x, y, z.
            # same x will mean a collision in the hashtable as bucket index is computed from
            # first 4 bytes. giving a specific x targets bucket index x.
            # y is to create different keys and does not go into the bucket index calculation.
            # so, same x + different y --> collision
            return pack("<IIIIIIII", x, y, z, 0, 0, 0, 0, 0)  # 8 * 4 == 32

        idx = NSIndex()

        # create lots of colliding entries
        for y in range(700):  # stay below max load not to trigger resize
            idx[HH(0, y, 0)] = (0, y, 0)

        assert idx.size() == 1024 + 1031 * 44  # header + 1031 buckets

        # delete lots of the collisions, creating lots of tombstones
        for y in range(400):  # stay above min load not to trigger resize
            del idx[HH(0, y, 0)]

        # create lots of colliding entries, within the not yet used part of the hashtable
        for y in range(330):  # stay below max load not to trigger resize
            # at y == 259 a resize will happen due to going beyond max EFFECTIVE load
            # if the bug is present, that element will be inserted at the wrong place.
            # and because it will be at the wrong place, it can not be found again.
            idx[HH(600, y, 0)] = 600, y, 0

        # now check if hashtable contents is as expected:

        assert [idx.get(HH(0, y, 0)) for y in range(400, 700)] == [(0, y, 0) for y in range(400, 700)]

        assert [HH(0, y, 0) in idx for y in range(400)] == [False for y in range(400)]  # deleted entries

        # this will fail at HH(600, 259) if the bug is present.
        assert [idx.get(HH(600, y, 0)) for y in range(330)] == [(600, y, 0) for y in range(330)]
