# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from io import BytesIO

from ...chunkers import get_chunker
from ...chunkers.buzhash64 import buzhash64, buzhash64_update, ChunkerBuzHash64
from ...constants import *  # NOQA
from ...helpers import hex_to_bin
from .. import BaseTestCase
from . import cf

# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")
key2 = hex_to_bin("57174a65fde67fe127b18430525b50a58406f1bd6cc629535208c7832e181067")


class ChunkerBuzHash64TestCase(BaseTestCase):
    def test_chunkify64(self):
        data = b"0" * int(1.5 * (1 << CHUNK_MAX_EXP)) + b"Y"
        parts = cf(ChunkerBuzHash64(key0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(data)))
        self.assert_equal(len(parts), 2)
        self.assert_equal(b"".join(parts), data)
        self.assert_equal(cf(ChunkerBuzHash64(key0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b""))), [])
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarb", b"ooba", b"zf", b"oobarb", b"ooba", b"zf", b"oobarb", b"oobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fo", b"oba", b"rb", b"oob", b"azf", b"ooba", b"rb", b"oob", b"azf", b"ooba", b"rb", b"oobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobar", b"booba", b"zfoobar", b"booba", b"zfoobar", b"boobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obaz", b"foobarbo", b"obaz", b"foobarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboob", b"azfoobarboob", b"azfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foob", b"arboobazfoob", b"arboobazfoob", b"arboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarbo", b"obazfoobarbo", b"obazfoobarbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboob", b"azfoobarboob", b"azfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobazfoob", b"arboobazfoob", b"arboobaz"],
        )

    def test_buzhash64(self):
        self.assert_equal(buzhash64(b"abcdefghijklmnop", key0), 17414563089559790077)
        self.assert_equal(buzhash64(b"abcdefghijklmnop", key1), 1397285894609271345)
        expected = buzhash64(b"abcdefghijklmnop", key0)
        previous = buzhash64(b"Xabcdefghijklmno", key0)
        this = buzhash64_update(previous, ord("X"), ord("p"), 16, key0)
        self.assert_equal(this, expected)
        # Test with more than 63 bytes to make sure our barrel_shift macro works correctly
        self.assert_equal(buzhash64(b"abcdefghijklmnopqrstuvwxyz" * 4, key0), 17683050804041322250)

    def test_small_reads64(self):
        class SmallReadFile:
            input = b"a" * (20 + 1)

            def read(self, nbytes):
                self.input = self.input[:-1]
                return self.input[:1]

        chunker = get_chunker(*CHUNKER64_PARAMS, sparse=False)
        reconstructed = b"".join(cf(chunker.chunkify(SmallReadFile())))
        assert reconstructed == b"a" * 20
