# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from io import BytesIO

from ...chunkers.buzhash64 import buzhash64, buzhash64_update, ChunkerBuzHash64
from ...constants import *  # NOQA
from .. import BaseTestCase
from . import cf


class ChunkerBuzHash64TestCase(BaseTestCase):
    def test_chunkify64(self):
        key0, key1, key2 = b"0" * 16, b"1" * 16, b"2" * 16
        data = b"0" * int(1.5 * (1 << CHUNK_MAX_EXP)) + b"Y"
        parts = cf(ChunkerBuzHash64(key0, 1, CHUNK_MAX_EXP, 2, 2, do_encrypt=False).chunkify(BytesIO(data)))
        self.assert_equal(len(parts), 2)
        self.assert_equal(b"".join(parts), data)
        self.assert_equal(
            cf(ChunkerBuzHash64(b"0" * 16, 1, CHUNK_MAX_EXP, 2, 2, do_encrypt=False).chunkify(BytesIO(b""))), []
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 1, CHUNK_MAX_EXP, 2, 2, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fo", b"oba", b"rbo", b"ob", b"azfo", b"oba", b"rbo", b"ob", b"azfo", b"oba", b"rbo", b"obaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 1, CHUNK_MAX_EXP, 2, 2, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fooba", b"rboobazfooba", b"rboobazfooba", b"rboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 1, CHUNK_MAX_EXP, 2, 2, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foo", b"barboo", b"bazfoo", b"barboo", b"bazfoo", b"barboo", b"baz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 2, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobar", b"boobazfoo", b"barboobazfoo", b"barboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 2, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboo", b"bazfoobarboo", b"bazfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 2, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"fooba", b"rboob", b"azfooba", b"rboob", b"azfooba", b"rboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key0, 3, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboobazfoo", b"barboobazfoo", b"barboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key1, 3, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboo", b"bazfoobarboo", b"bazfoobarboobaz"],
        )
        self.assert_equal(
            cf(ChunkerBuzHash64(key2, 3, CHUNK_MAX_EXP, 2, 3, do_encrypt=False).chunkify(BytesIO(b"foobarboobaz" * 3))),
            [b"foobarboob", b"azfoobarboob", b"azfoobarboobaz"],
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

        # Explicitly create the chunker with the same parameters as CHUNKER64_PARAMS
        # but also specify do_encrypt=True.
        chunker = ChunkerBuzHash64(
            b"0" * 16, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE, sparse=False, do_encrypt=True
        )
        reconstructed = b"".join(cf(chunker.chunkify(SmallReadFile())))
        assert reconstructed == b"a" * 20
