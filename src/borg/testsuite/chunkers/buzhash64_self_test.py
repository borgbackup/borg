# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from io import BytesIO

from ...chunkers import get_chunker
from ...chunkers.buzhash64 import buzhash64, buzhash64_update, ChunkerBuzHash64
from ...constants import *  # NOQA
from .. import BaseTestCase
from . import cf


class ChunkerBuzHash64TestCase(BaseTestCase):
    def test_chunkify64(self):
        data = b"0" * int(1.5 * (1 << CHUNK_MAX_EXP)) + b"Y"
        parts = cf(ChunkerBuzHash64(b"0", 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(data)))
        self.assert_equal(len(parts), 2)
        self.assert_equal(b"".join(parts), data)
        self.assert_equal(cf(ChunkerBuzHash64(b"0", 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b""))), [])
        self.assert_equal(
            cf(ChunkerBuzHash64(b"0", 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fo", b"obarbo", b"ob", b"azfo", b"obarbo", b"ob", b"azfo", b"obarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"1", 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fooba", b"rboobaz", b"fooba", b"rboobaz", b"fooba", b"rboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"2", 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foob", b"arboobazfoob", b"arboobazfoob", b"arboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"0", 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarb", b"oobaz", b"foobarb", b"oobaz", b"foobarb", b"oobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"1", 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfo", b"obarbo", b"obazfo", b"obarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"2", 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobaz", b"foobarboobaz", b"foobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"0", 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfoobarb", b"oobazfoo", b"barboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"1", 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfoobarbo", b"obazfoobarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(b"2", 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobaz", b"foobarboobaz", b"foobarboobaz"],
        )

    def test_buzhash64(self):
        self.assert_equal(buzhash64(b"abcdefghijklmnop", b"0"), 13095190927899934478)
        self.assert_equal(buzhash64(b"abcdefghijklmnop", b"1"), 10129419249308136910)
        expected = buzhash64(b"abcdefghijklmnop", b"1")
        previous = buzhash64(b"Xabcdefghijklmno", b"1")
        this = buzhash64_update(previous, ord("X"), ord("p"), 16, b"1")
        self.assert_equal(this, expected)
        # Test with more than 63 bytes to make sure our barrel_shift macro works correctly
        self.assert_equal(buzhash64(b"abcdefghijklmnopqrstuvwxyz" * 4, b"0"), 9064183923498167899)

    def test_small_reads64(self):
        class SmallReadFile:
            input = b"a" * (20 + 1)

            def read(self, nbytes):
                self.input = self.input[:-1]
                return self.input[:1]

        chunker = get_chunker(*CHUNKER64_PARAMS, sparse=False)
        reconstructed = b"".join(cf(chunker.chunkify(SmallReadFile())))
        assert reconstructed == b"a" * 20
