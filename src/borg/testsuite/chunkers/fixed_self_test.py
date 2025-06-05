# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

from io import BytesIO

from ...chunkers.fixed import ChunkerFixed
from ...constants import *  # NOQA
from .. import BaseTestCase
from . import cf


class ChunkerFixedTestCase(BaseTestCase):
    def test_chunkify_just_blocks(self):
        data = b"foobar" * 1500
        chunker = ChunkerFixed(4096)
        parts = cf(chunker.chunkify(BytesIO(data)))
        self.assert_equal(parts, [data[0:4096], data[4096:8192], data[8192:]])

    def test_chunkify_header_and_blocks(self):
        data = b"foobar" * 1500
        chunker = ChunkerFixed(4096, 123)
        parts = cf(chunker.chunkify(BytesIO(data)))
        self.assert_equal(
            parts, [data[0:123], data[123 : 123 + 4096], data[123 + 4096 : 123 + 8192], data[123 + 8192 :]]
        )

    def test_chunkify_just_blocks_fmap_complete(self):
        data = b"foobar" * 1500
        chunker = ChunkerFixed(4096)
        fmap = [(0, 4096, True), (4096, 8192, True), (8192, 99999999, True)]
        parts = cf(chunker.chunkify(BytesIO(data), fmap=fmap))
        self.assert_equal(parts, [data[0:4096], data[4096:8192], data[8192:]])

    def test_chunkify_header_and_blocks_fmap_complete(self):
        data = b"foobar" * 1500
        chunker = ChunkerFixed(4096, 123)
        fmap = [(0, 123, True), (123, 4096, True), (123 + 4096, 4096, True), (123 + 8192, 4096, True)]
        parts = cf(chunker.chunkify(BytesIO(data), fmap=fmap))
        self.assert_equal(
            parts, [data[0:123], data[123 : 123 + 4096], data[123 + 4096 : 123 + 8192], data[123 + 8192 :]]
        )

    def test_chunkify_header_and_blocks_fmap_zeros(self):
        data = b"H" * 123 + b"_" * 4096 + b"X" * 4096 + b"_" * 4096
        chunker = ChunkerFixed(4096, 123)
        fmap = [(0, 123, True), (123, 4096, False), (123 + 4096, 4096, True), (123 + 8192, 4096, False)]
        parts = cf(chunker.chunkify(BytesIO(data), fmap=fmap))
        # because we marked the '_' ranges as holes, we will get hole ranges instead!
        self.assert_equal(parts, [data[0:123], 4096, data[123 + 4096 : 123 + 8192], 4096])

    def test_chunkify_header_and_blocks_fmap_partial(self):
        data = b"H" * 123 + b"_" * 4096 + b"X" * 4096 + b"_" * 4096
        chunker = ChunkerFixed(4096, 123)
        fmap = [
            (0, 123, True),
            # (123, 4096, False),
            (123 + 4096, 4096, True),
            # (123+8192, 4096, False),
        ]
        parts = cf(chunker.chunkify(BytesIO(data), fmap=fmap))
        # because we left out the '_' ranges from the fmap, we will not get them at all!
        self.assert_equal(parts, [data[0:123], data[123 + 4096 : 123 + 8192]])
