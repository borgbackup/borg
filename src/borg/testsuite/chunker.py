from io import BytesIO

from ..chunker import ChunkerFixed, Chunker, get_chunker, buzhash, buzhash_perm, buzhash_update, buzhash_update_perm
from ..constants import *  # NOQA
from . import BaseTestCase

# Note: these tests are part of the self test, do not use or import py.test functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT


null_permutation = bytes(range(256))


def permutation_invert_case():
    perm = list(range(256))
    for up in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        low = up.lower()
        perm[ord(low)] = ord(up)
        perm[ord(up)] = ord(low)
    return bytes(perm)


class ChunkerFixedTestCase(BaseTestCase):

    def test_chunkify_just_blocks(self):
        data = b'foobar' * 1500
        chunker = ChunkerFixed(4096)
        parts = [c for c in chunker.chunkify(BytesIO(data))]
        self.assert_equal(parts, [data[0:4096], data[4096:8192], data[8192:]])

    def test_chunkify_header_and_blocks(self):
        data = b'foobar' * 1500
        chunker = ChunkerFixed(4096, 123)
        parts = [c for c in chunker.chunkify(BytesIO(data))]
        self.assert_equal(parts, [data[0:123], data[123:123+4096], data[123+4096:123+8192], data[123+8192:]])


class ChunkerTestCase(BaseTestCase):

    def test_chunkify(self):
        np = null_permutation
        data = b'0' * int(1.5 * (1 << CHUNK_MAX_EXP)) + b'Y'
        parts = [bytes(c) for c in Chunker(0, np, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(data))]
        self.assert_equal(len(parts), 2)
        self.assert_equal(b''.join(parts), data)
        self.assert_equal([bytes(c) for c in Chunker(0, np, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b''))], [])
        self.assert_equal([bytes(c) for c in Chunker(0, np, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'fooba', b'rboobaz', b'fooba', b'rboobaz', b'fooba', b'rboobaz'])
        self.assert_equal([bytes(c) for c in Chunker(1, np, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'fo', b'obarb', b'oob', b'azf', b'oobarb', b'oob', b'azf', b'oobarb', b'oobaz'])
        self.assert_equal([bytes(c) for c in Chunker(2, np, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foob', b'ar', b'boobazfoob', b'ar', b'boobazfoob', b'ar', b'boobaz'])
        self.assert_equal([bytes(c) for c in Chunker(0, np, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz' * 3])
        self.assert_equal([bytes(c) for c in Chunker(1, np, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobar', b'boobazfo', b'obar', b'boobazfo', b'obar', b'boobaz'])
        self.assert_equal([bytes(c) for c in Chunker(2, np, 2, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foob', b'arboobaz', b'foob', b'arboobaz', b'foob', b'arboobaz'])
        self.assert_equal([bytes(c) for c in Chunker(0, np, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz' * 3])
        self.assert_equal([bytes(c) for c in Chunker(1, np, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarbo', b'obazfoobar', b'boobazfo', b'obarboobaz'])
        self.assert_equal([bytes(c) for c in Chunker(2, np, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz', b'foobarboobaz', b'foobarboobaz'])

    def test_buzhash(self):
        self.assert_equal(buzhash(b'abcdefghijklmnop', 0), 3795437769)
        self.assert_equal(buzhash(b'abcdefghijklmnop', 1), 3795400502)
        self.assert_equal(buzhash(b'abcdefghijklmnop', 1), buzhash_update(buzhash(b'Xabcdefghijklmno', 1), ord('X'), ord('p'), 16, 1))
        # Test with more than 31 bytes to make sure our barrel_shift macro works correctly
        self.assert_equal(buzhash(b'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz', 0), 566521248)

    def test_permutation(self):
        p = permutation_invert_case()

        # a non-null permutation should spoil these test cases copied from the methods above
        self.assert_not_equal([bytes(c) for c in Chunker(2, p, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'foobarboobaz' * 3))], [b'foobarboobaz', b'foobarboobaz', b'foobarboobaz'])
        self.assert_not_equal(buzhash_perm(b'abcdefghijklmnop', 0, p), 3795437769)

        # inverting the case of the input should compensate for the permutation
        self.assert_equal([bytes(c) for c in Chunker(0, p, 1, CHUNK_MAX_EXP, 2, 2).chunkify(BytesIO(b'FOOBARBOOBAZ' * 3))], [b'FOOBA', b'RBOOBAZ', b'FOOBA', b'RBOOBAZ', b'FOOBA', b'RBOOBAZ'])
        self.assert_equal([bytes(c) for c in Chunker(2, p, 3, CHUNK_MAX_EXP, 2, 3).chunkify(BytesIO(b'FOOBARBOOBAZ' * 3))], [b'FOOBARBOOBAZ', b'FOOBARBOOBAZ', b'FOOBARBOOBAZ'])
        self.assert_equal(buzhash_perm(b'ABCDEFGHIJKLMNOP', 0, p), 3795437769)
        self.assert_equal(buzhash_perm(b'ABCDEFGHIJKLMNOP', 1, p), 3795400502)
        self.assert_equal(buzhash_perm(b'ABCDEFGHIJKLMNOP', 1, p),
                          buzhash_update_perm(buzhash_perm(b'xABCDEFGHIJKLMNO', 1, p), ord('x'), ord('P'), 16, 1, p))

    def test_small_reads(self):
        class SmallReadFile:
            input = b'a' * (20 + 1)

            def read(self, nbytes):
                self.input = self.input[:-1]
                return self.input[:1]

        chunker = get_chunker(*CHUNKER_PARAMS, seed=0)
        reconstructed = b''.join(chunker.chunkify(SmallReadFile()))
        assert reconstructed == b'a' * 20
