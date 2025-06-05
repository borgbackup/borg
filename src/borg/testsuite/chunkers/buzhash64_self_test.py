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
        parts = cf(ChunkerBuzHash64(0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(data)))
        self.assert_equal(len(parts), 2)
        self.assert_equal(b"".join(parts), data)
        self.assert_equal(cf(ChunkerBuzHash64(0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b""))), [])
        self.assert_equal(
            cf(ChunkerBuzHash64(0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fo", b"oba", b"rbo", b"ob", b"azfo", b"oba", b"rbo", b"ob", b"azfo", b"oba", b"rbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(1, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobazfoobarboobazfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(2, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboob", b"azfoobarboob", b"azfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(0, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobar", b"boobazfoo", b"barboobazfoo", b"barboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(1, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbooba", b"zfoobarbooba", b"zfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(2, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfo", b"obarbo", b"obazfo", b"obarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(0, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobazfoo", b"barboobazfoo", b"barboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(1, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbooba", b"zfoobarbooba", b"zfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(2, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfoobarbo", b"obazfoobarbo", b"obaz"],
        )

    def test_buzhash64(self):
        self.assert_equal(buzhash64(b"abcdefghijklmnop", 0), 13314711829666336849)
        self.assert_equal(buzhash64(b"abcdefghijklmnop", 1), 17807676237451361719)
        expected = buzhash64(b"abcdefghijklmnop", 1)
        previous = buzhash64(b"Xabcdefghijklmno", 1)
        this = buzhash64_update(previous, ord("X"), ord("p"), 16, 1)
        self.assert_equal(this, expected)
        # Test with more than 63 bytes to make sure our barrel_shift macro works correctly
        self.assert_equal(buzhash64(b"abcdefghijklmnopqrstuvwxyz" * 4, 0), 592868834756664313)

    def test_small_reads64(self):
        class SmallReadFile:
            input = b"a" * (20 + 1)

            def read(self, nbytes):
                self.input = self.input[:-1]
                return self.input[:1]

        chunker = get_chunker(*CHUNKER64_PARAMS, sparse=False)
        reconstructed = b"".join(cf(chunker.chunkify(SmallReadFile())))
        assert reconstructed == b"a" * 20
