from io import BytesIO

from ..chunker import Chunker, buzhash, buzhash_update
from ..archive import CHUNK_MAX
from . import BaseTestCase


class ChunkerTestCase(BaseTestCase):

    def test_chunkify(self):
        data = b'0' * int(1.5 * CHUNK_MAX) + b'Y'
        parts = [bytes(c) for c in Chunker(2, 0x3, 2, CHUNK_MAX, 0).chunkify(BytesIO(data))]
        self.assert_equal(len(parts), 2)
        self.assert_equal(b''.join(parts), data)
        self.assert_equal([bytes(c) for c in Chunker(2, 0x3, 2, CHUNK_MAX, 0).chunkify(BytesIO(b''))], [])
        self.assert_equal([bytes(c) for c in Chunker(2, 0x3, 2, CHUNK_MAX, 0).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'fooba', b'rboobaz', b'fooba', b'rboobaz', b'fooba', b'rboobaz'])
        self.assert_equal([bytes(c) for c in Chunker(2, 0x3, 2, CHUNK_MAX, 1).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'fo', b'obarb', b'oob', b'azf', b'oobarb', b'oob', b'azf', b'oobarb', b'oobaz'])
        self.assert_equal([bytes(c) for c in Chunker(2, 0x3, 2, CHUNK_MAX, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foob', b'ar', b'boobazfoob', b'ar', b'boobazfoob', b'ar', b'boobaz'])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 3, CHUNK_MAX, 0).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz' * 3])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 3, CHUNK_MAX, 1).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobar', b'boo', b'bazfo', b'obar', b'boo', b'bazfo', b'obar', b'boobaz'])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 3, CHUNK_MAX, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foo', b'barboobaz', b'foo', b'barboobaz', b'foo', b'barboobaz'])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 4, CHUNK_MAX, 0).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz' * 3])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 4, CHUNK_MAX, 1).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobar', b'boobazfo', b'obar', b'boobazfo', b'obar', b'boobaz'])
        self.assert_equal([bytes(c) for c in Chunker(3, 0x3, 4, CHUNK_MAX, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foob', b'arboobaz', b'foob', b'arboobaz', b'foob', b'arboobaz'])

    def test_buzhash(self):
        self.assert_equal(buzhash(b'abcdefghijklmnop', 0), 3795437769)
        self.assert_equal(buzhash(b'abcdefghijklmnop', 1), 3795400502)
        self.assert_equal(buzhash(b'abcdefghijklmnop', 1), buzhash_update(buzhash(b'Xabcdefghijklmno', 1), ord('X'), ord('p'), 16, 1))
        # Test with more than 31 bytes to make sure our barrel_shift macro works correctly
        self.assert_equal(buzhash(b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz', 0), 566521248)
