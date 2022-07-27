# Note: these tests are part of the self test, do not use or import pytest functionality here.
#       See borg.selftest for details. If you add/remove test methods, update SELFTEST_COUNT

import base64
import hashlib
import io
import os
import tempfile
import zlib

from ..hashindex import NSIndex, ChunkIndex, ChunkIndexEntry
from ..crypto.file_integrity import IntegrityCheckedFile, FileIntegrityError
from . import BaseTestCase, unopened_tempfile


def H(x):
    # make some 32byte long thing that depends on x
    return bytes("%-0.32d" % x, "ascii")


def H2(x):
    # like H(x), but with pseudo-random distribution of the output value
    return hashlib.sha256(H(x)).digest()


class HashIndexTestCase(BaseTestCase):
    def _generic_test(self, cls, make_value, sha):
        idx = cls()
        self.assert_equal(len(idx), 0)
        # Test set
        for x in range(100):
            idx[H(x)] = make_value(x)
        self.assert_equal(len(idx), 100)
        for x in range(100):
            self.assert_equal(idx[H(x)], make_value(x))
        # Test update
        for x in range(100):
            idx[H(x)] = make_value(x * 2)
        self.assert_equal(len(idx), 100)
        for x in range(100):
            self.assert_equal(idx[H(x)], make_value(x * 2))
        # Test delete
        for x in range(50):
            del idx[H(x)]
        # Test some keys still in there
        for x in range(50, 100):
            assert H(x) in idx
        # Test some keys not there any more
        for x in range(50):
            assert H(x) not in idx
        # Test delete non-existing key
        for x in range(50):
            self.assert_raises(KeyError, idx.__delitem__, H(x))
        self.assert_equal(len(idx), 50)
        with unopened_tempfile() as filepath:
            idx.write(filepath)
            del idx
            # Verify file contents
            with open(filepath, "rb") as fd:
                self.assert_equal(hashlib.sha256(fd.read()).hexdigest(), sha)
            # Make sure we can open the file
            idx = cls.read(filepath)
            self.assert_equal(len(idx), 50)
            for x in range(50, 100):
                self.assert_equal(idx[H(x)], make_value(x * 2))
            idx.clear()
            self.assert_equal(len(idx), 0)
            idx.write(filepath)
            del idx
            self.assert_equal(len(cls.read(filepath)), 0)
        idx = cls()
        # Test setdefault - set non-existing key
        idx.setdefault(H(0), make_value(42))
        assert H(0) in idx
        assert idx[H(0)] == make_value(42)
        # Test setdefault - do not set existing key
        idx.setdefault(H(0), make_value(23))
        assert H(0) in idx
        assert idx[H(0)] == make_value(42)
        # Test setdefault - get-like return value, key not present
        assert idx.setdefault(H(1), make_value(23)) == make_value(23)
        # Test setdefault - get-like return value, key present
        assert idx.setdefault(H(0), make_value(23)) == make_value(42)
        # clean up setdefault test
        del idx

    def test_nsindex(self):
        self._generic_test(
            NSIndex, lambda x: (x, x, x), "7d70671d0b7e9d2f51b2691ecf35184b9f8ecc1202cceb2748c905c8fc04c256"
        )

    def test_chunkindex(self):
        self._generic_test(
            ChunkIndex, lambda x: (x, x), "85f72b036c692c8266e4f51ccf0cff2147204282b5e316ae508d30a448d88fef"
        )

    def test_resize(self):
        n = 2000  # Must be >= MIN_BUCKETS
        with unopened_tempfile() as filepath:
            idx = NSIndex()
            idx.write(filepath)
            initial_size = os.path.getsize(filepath)
            self.assert_equal(len(idx), 0)
            for x in range(n):
                idx[H(x)] = x, x, x, x
            idx.write(filepath)
            assert initial_size < os.path.getsize(filepath)
            for x in range(n):
                del idx[H(x)]
            self.assert_equal(len(idx), 0)
            idx.write(filepath)
            self.assert_equal(initial_size, os.path.getsize(filepath))

    def test_iteritems(self):
        idx = NSIndex()
        for x in range(100):
            idx[H(x)] = x, x, x, x
        iterator = idx.iteritems()
        all = list(iterator)
        self.assert_equal(len(all), 100)
        # iterator is already exhausted by list():
        self.assert_raises(StopIteration, next, iterator)
        second_half = list(idx.iteritems(marker=all[49][0]))
        self.assert_equal(len(second_half), 50)
        self.assert_equal(second_half, all[50:])

    def test_chunkindex_merge(self):
        idx1 = ChunkIndex()
        idx1[H(1)] = 1, 100
        idx1[H(2)] = 2, 200
        idx1[H(3)] = 3, 300
        # no H(4) entry
        idx2 = ChunkIndex()
        idx2[H(1)] = 4, 100
        idx2[H(2)] = 5, 200
        # no H(3) entry
        idx2[H(4)] = 6, 400
        idx1.merge(idx2)
        assert idx1[H(1)] == (5, 100)
        assert idx1[H(2)] == (7, 200)
        assert idx1[H(3)] == (3, 300)
        assert idx1[H(4)] == (6, 400)

    def test_chunkindex_summarize(self):
        idx = ChunkIndex()
        idx[H(1)] = 1, 1000
        idx[H(2)] = 2, 2000
        idx[H(3)] = 3, 3000

        size, unique_size, unique_chunks, chunks = idx.summarize()
        assert size == 1000 + 2 * 2000 + 3 * 3000
        assert unique_size == 1000 + 2000 + 3000
        assert chunks == 1 + 2 + 3
        assert unique_chunks == 3

    def test_flags(self):
        idx = NSIndex()
        key = H(0)
        self.assert_raises(KeyError, idx.flags, key, 0)
        idx[key] = 0, 0, 0  # create entry
        # check bit 0 and 1, should be both 0 after entry creation
        self.assert_equal(idx.flags(key, mask=3), 0)
        # set bit 0
        idx.flags(key, mask=1, value=1)
        self.assert_equal(idx.flags(key, mask=1), 1)
        # set bit 1
        idx.flags(key, mask=2, value=2)
        self.assert_equal(idx.flags(key, mask=2), 2)
        # check both bit 0 and 1, both should be set
        self.assert_equal(idx.flags(key, mask=3), 3)
        # clear bit 1
        idx.flags(key, mask=2, value=0)
        self.assert_equal(idx.flags(key, mask=2), 0)
        # clear bit 0
        idx.flags(key, mask=1, value=0)
        self.assert_equal(idx.flags(key, mask=1), 0)
        # check both bit 0 and 1, both should be cleared
        self.assert_equal(idx.flags(key, mask=3), 0)

    def test_flags_iteritems(self):
        idx = NSIndex()
        keys_flagged0 = {H(i) for i in (1, 2, 3, 42)}
        keys_flagged1 = {H(i) for i in (11, 12, 13, 142)}
        keys_flagged2 = {H(i) for i in (21, 22, 23, 242)}
        keys_flagged3 = {H(i) for i in (31, 32, 33, 342)}
        for key in keys_flagged0:
            idx[key] = 0, 0, 0  # create entry
            idx.flags(key, mask=3, value=0)  # not really necessary, unflagged is default
        for key in keys_flagged1:
            idx[key] = 0, 0, 0  # create entry
            idx.flags(key, mask=3, value=1)
        for key in keys_flagged2:
            idx[key] = 0, 0, 0  # create entry
            idx.flags(key, mask=3, value=2)
        for key in keys_flagged3:
            idx[key] = 0, 0, 0  # create entry
            idx.flags(key, mask=3, value=3)
        # check if we can iterate over all items
        k_all = {k for k, v in idx.iteritems()}
        self.assert_equal(k_all, keys_flagged0 | keys_flagged1 | keys_flagged2 | keys_flagged3)
        # check if we can iterate over the flagged0 items
        k0 = {k for k, v in idx.iteritems(mask=3, value=0)}
        self.assert_equal(k0, keys_flagged0)
        # check if we can iterate over the flagged1 items
        k1 = {k for k, v in idx.iteritems(mask=3, value=1)}
        self.assert_equal(k1, keys_flagged1)
        # check if we can iterate over the flagged2 items
        k1 = {k for k, v in idx.iteritems(mask=3, value=2)}
        self.assert_equal(k1, keys_flagged2)
        # check if we can iterate over the flagged3 items
        k1 = {k for k, v in idx.iteritems(mask=3, value=3)}
        self.assert_equal(k1, keys_flagged3)
        # check if we can iterate over the flagged1 + flagged3 items
        k1 = {k for k, v in idx.iteritems(mask=1, value=1)}
        self.assert_equal(k1, keys_flagged1 | keys_flagged3)
        # check if we can iterate over the flagged0 + flagged2 items
        k1 = {k for k, v in idx.iteritems(mask=1, value=0)}
        self.assert_equal(k1, keys_flagged0 | keys_flagged2)


class HashIndexExtraTestCase(BaseTestCase):
    """These tests are separate because they should not become part of the selftest."""

    def test_chunk_indexer(self):
        # see _hashindex.c hash_sizes, we want to be close to the max. load
        # because interesting errors happen there.
        key_count = int(65537 * ChunkIndex.MAX_LOAD_FACTOR) - 10
        index = ChunkIndex(key_count)
        all_keys = [hashlib.sha256(H(k)).digest() for k in range(key_count)]
        # we're gonna delete 1/3 of all_keys, so let's split them 2/3 and 1/3:
        keys, to_delete_keys = all_keys[0 : (2 * key_count // 3)], all_keys[(2 * key_count // 3) :]

        for i, key in enumerate(keys):
            index[key] = (i, i)
        for i, key in enumerate(to_delete_keys):
            index[key] = (i, i)

        for key in to_delete_keys:
            del index[key]
        for i, key in enumerate(keys):
            assert index[key] == (i, i)
        for key in to_delete_keys:
            assert index.get(key) is None

        # now delete every key still in the index
        for key in keys:
            del index[key]
        # the index should now be empty
        assert list(index.iteritems()) == []


class HashIndexSizeTestCase(BaseTestCase):
    def test_size_on_disk(self):
        idx = ChunkIndex()
        assert idx.size() == 18 + 1031 * (32 + 2 * 4)

    def test_size_on_disk_accurate(self):
        idx = ChunkIndex()
        for i in range(1234):
            idx[H(i)] = i, i**2
        with tempfile.NamedTemporaryFile() as file:
            idx.write(file.name)
            size = os.path.getsize(file.name)
        assert idx.size() == size


class HashIndexRefcountingTestCase(BaseTestCase):
    def test_chunkindex_limit(self):
        idx = ChunkIndex()
        idx[H(1)] = ChunkIndex.MAX_VALUE - 1, 1

        # 5 is arbitrary, any number of incref/decrefs shouldn't move it once it's limited
        for i in range(5):
            # first incref to move it to the limit
            refcount, *_ = idx.incref(H(1))
            assert refcount == ChunkIndex.MAX_VALUE
        for i in range(5):
            refcount, *_ = idx.decref(H(1))
            assert refcount == ChunkIndex.MAX_VALUE

    def _merge(self, refcounta, refcountb):
        def merge(refcount1, refcount2):
            idx1 = ChunkIndex()
            idx1[H(1)] = refcount1, 1
            idx2 = ChunkIndex()
            idx2[H(1)] = refcount2, 1
            idx1.merge(idx2)
            refcount, *_ = idx1[H(1)]
            return refcount

        result = merge(refcounta, refcountb)
        # check for commutativity
        assert result == merge(refcountb, refcounta)
        return result

    def test_chunkindex_merge_limit1(self):
        # Check that it does *not* limit at MAX_VALUE - 1
        # (MAX_VALUE is odd)
        half = ChunkIndex.MAX_VALUE // 2
        assert self._merge(half, half) == ChunkIndex.MAX_VALUE - 1

    def test_chunkindex_merge_limit2(self):
        # 3000000000 + 2000000000 > MAX_VALUE
        assert self._merge(3000000000, 2000000000) == ChunkIndex.MAX_VALUE

    def test_chunkindex_merge_limit3(self):
        # Crossover point: both addition and limit semantics will yield the same result
        half = ChunkIndex.MAX_VALUE // 2
        assert self._merge(half + 1, half) == ChunkIndex.MAX_VALUE

    def test_chunkindex_merge_limit4(self):
        # Beyond crossover, result of addition would be 2**31
        half = ChunkIndex.MAX_VALUE // 2
        assert self._merge(half + 2, half) == ChunkIndex.MAX_VALUE
        assert self._merge(half + 1, half + 1) == ChunkIndex.MAX_VALUE

    def test_chunkindex_add(self):
        idx1 = ChunkIndex()
        idx1.add(H(1), 5, 6)
        assert idx1[H(1)] == (5, 6)
        idx1.add(H(1), 1, 2)
        assert idx1[H(1)] == (6, 2)

    def test_incref_limit(self):
        idx1 = ChunkIndex()
        idx1[H(1)] = ChunkIndex.MAX_VALUE, 6
        idx1.incref(H(1))
        refcount, *_ = idx1[H(1)]
        assert refcount == ChunkIndex.MAX_VALUE

    def test_decref_limit(self):
        idx1 = ChunkIndex()
        idx1[H(1)] = ChunkIndex.MAX_VALUE, 6
        idx1.decref(H(1))
        refcount, *_ = idx1[H(1)]
        assert refcount == ChunkIndex.MAX_VALUE

    def test_decref_zero(self):
        idx1 = ChunkIndex()
        idx1[H(1)] = 0, 0
        with self.assert_raises(AssertionError):
            idx1.decref(H(1))

    def test_incref_decref(self):
        idx1 = ChunkIndex()
        idx1.add(H(1), 5, 6)
        assert idx1[H(1)] == (5, 6)
        idx1.incref(H(1))
        assert idx1[H(1)] == (6, 6)
        idx1.decref(H(1))
        assert idx1[H(1)] == (5, 6)

    def test_setitem_raises(self):
        idx1 = ChunkIndex()
        with self.assert_raises(AssertionError):
            idx1[H(1)] = ChunkIndex.MAX_VALUE + 1, 0

    def test_keyerror(self):
        idx = ChunkIndex()
        with self.assert_raises(KeyError):
            idx.incref(H(1))
        with self.assert_raises(KeyError):
            idx.decref(H(1))
        with self.assert_raises(KeyError):
            idx[H(1)]
        with self.assert_raises(OverflowError):
            idx.add(H(1), -1, 0)


class HashIndexDataTestCase(BaseTestCase):
    # This bytestring was created with borg2-pre 2022-06-10
    HASHINDEX = (
        b"eJzt0LEJg1AYhdE/JqBjOEJMNhBBrAQrO9ewc+HsoG+CPMsEz1cfbnHbceqXoZvvEVE+IuoqMu2pnOE4"
        b"juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4juM4"
        b"juM4juM4juM4jruie36vuSVT5N0rzW0n9t7r5z9+4TiO4ziO4ziO4ziO4ziO4ziO4ziO4ziO4ziO4ziO"
        b"4ziO4ziO4ziO4ziO4ziO437LHbSVHGw="
    )

    def _serialize_hashindex(self, idx):
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, "idx")
            idx.write(file)
            with open(file, "rb") as f:
                return self._pack(f.read())

    def _deserialize_hashindex(self, bytestring):
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, "idx")
            with open(file, "wb") as f:
                f.write(self._unpack(bytestring))
            return ChunkIndex.read(file)

    def _pack(self, bytestring):
        return base64.b64encode(zlib.compress(bytestring))

    def _unpack(self, bytestring):
        return zlib.decompress(base64.b64decode(bytestring))

    def test_identical_creation(self):
        idx1 = ChunkIndex()
        idx1[H(1)] = 1, 2
        idx1[H(2)] = 2**31 - 1, 0
        idx1[H(3)] = 4294962296, 0  # 4294962296 is -5000 interpreted as an uint32_t

        serialized = self._serialize_hashindex(idx1)
        assert self._unpack(serialized) == self._unpack(self.HASHINDEX)

    def test_read_known_good(self):
        idx1 = self._deserialize_hashindex(self.HASHINDEX)
        assert idx1[H(1)] == (1, 2)
        assert idx1[H(2)] == (2**31 - 1, 0)
        assert idx1[H(3)] == (4294962296, 0)

        idx2 = ChunkIndex()
        idx2[H(3)] = 2**32 - 123456, 6
        idx1.merge(idx2)
        assert idx1[H(3)] == (ChunkIndex.MAX_VALUE, 6)


class HashIndexIntegrityTestCase(HashIndexDataTestCase):
    def write_integrity_checked_index(self, tempdir):
        idx = self._deserialize_hashindex(self.HASHINDEX)
        file = os.path.join(tempdir, "idx")
        with IntegrityCheckedFile(path=file, write=True) as fd:
            idx.write(fd)
        integrity_data = fd.integrity_data
        assert "final" in integrity_data
        assert "HashHeader" in integrity_data
        return file, integrity_data

    def test_integrity_checked_file(self):
        with tempfile.TemporaryDirectory() as tempdir:
            file, integrity_data = self.write_integrity_checked_index(tempdir)
            with open(file, "r+b") as fd:
                fd.write(b"Foo")
            with self.assert_raises(FileIntegrityError):
                with IntegrityCheckedFile(path=file, write=False, integrity_data=integrity_data) as fd:
                    ChunkIndex.read(fd)


class HashIndexCompactTestCase(HashIndexDataTestCase):
    def index(self, num_entries, num_buckets):
        index_data = io.BytesIO()
        index_data.write(b"BORG_IDX")
        # num_entries
        index_data.write(num_entries.to_bytes(4, "little"))
        # num_buckets
        index_data.write(num_buckets.to_bytes(4, "little"))
        # key_size
        index_data.write((32).to_bytes(1, "little"))
        # value_size
        index_data.write((3 * 4).to_bytes(1, "little"))

        self.index_data = index_data

    def index_from_data(self):
        self.index_data.seek(0)
        index = ChunkIndex.read(self.index_data)
        return index

    def index_to_data(self, index):
        data = io.BytesIO()
        index.write(data)
        return data.getvalue()

    def index_from_data_compact_to_data(self):
        index = self.index_from_data()
        index.compact()
        compact_index = self.index_to_data(index)
        return compact_index

    def write_entry(self, key, *values):
        self.index_data.write(key)
        for value in values:
            self.index_data.write(value.to_bytes(4, "little"))

    def write_empty(self, key):
        self.write_entry(key, 0xFFFFFFFF, 0, 0)

    def write_deleted(self, key):
        self.write_entry(key, 0xFFFFFFFE, 0, 0)

    def test_simple(self):
        self.index(num_entries=3, num_buckets=6)
        self.write_entry(H2(0), 1, 2, 3)
        self.write_deleted(H2(1))
        self.write_empty(H2(2))
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        self.write_empty(H2(5))

        compact_index = self.index_from_data_compact_to_data()

        self.index(num_entries=3, num_buckets=3)
        self.write_entry(H2(0), 1, 2, 3)
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        assert compact_index == self.index_data.getvalue()

    def test_first_empty(self):
        self.index(num_entries=3, num_buckets=6)
        self.write_deleted(H2(1))
        self.write_entry(H2(0), 1, 2, 3)
        self.write_empty(H2(2))
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        self.write_empty(H2(5))

        compact_index = self.index_from_data_compact_to_data()

        self.index(num_entries=3, num_buckets=3)
        self.write_entry(H2(0), 1, 2, 3)
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        assert compact_index == self.index_data.getvalue()

    def test_last_used(self):
        self.index(num_entries=3, num_buckets=6)
        self.write_deleted(H2(1))
        self.write_entry(H2(0), 1, 2, 3)
        self.write_empty(H2(2))
        self.write_entry(H2(3), 5, 6, 7)
        self.write_empty(H2(5))
        self.write_entry(H2(4), 8, 9, 10)

        compact_index = self.index_from_data_compact_to_data()

        self.index(num_entries=3, num_buckets=3)
        self.write_entry(H2(0), 1, 2, 3)
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        assert compact_index == self.index_data.getvalue()

    def test_too_few_empty_slots(self):
        self.index(num_entries=3, num_buckets=6)
        self.write_deleted(H2(1))
        self.write_entry(H2(0), 1, 2, 3)
        self.write_entry(H2(3), 5, 6, 7)
        self.write_empty(H2(2))
        self.write_empty(H2(5))
        self.write_entry(H2(4), 8, 9, 10)

        compact_index = self.index_from_data_compact_to_data()

        self.index(num_entries=3, num_buckets=3)
        self.write_entry(H2(0), 1, 2, 3)
        self.write_entry(H2(3), 5, 6, 7)
        self.write_entry(H2(4), 8, 9, 10)
        assert compact_index == self.index_data.getvalue()

    def test_empty(self):
        self.index(num_entries=0, num_buckets=6)
        self.write_deleted(H2(1))
        self.write_empty(H2(0))
        self.write_deleted(H2(3))
        self.write_empty(H2(2))
        self.write_empty(H2(5))
        self.write_deleted(H2(4))

        compact_index = self.index_from_data_compact_to_data()

        self.index(num_entries=0, num_buckets=0)
        assert compact_index == self.index_data.getvalue()

    def test_merge(self):
        master = ChunkIndex()
        idx1 = ChunkIndex()
        idx1[H(1)] = 1, 100
        idx1[H(2)] = 2, 200
        idx1[H(3)] = 3, 300
        idx1.compact()
        assert idx1.size() == 18 + 3 * (32 + 2 * 4)

        master.merge(idx1)
        assert master[H(1)] == (1, 100)
        assert master[H(2)] == (2, 200)
        assert master[H(3)] == (3, 300)


class NSIndexTestCase(BaseTestCase):
    def test_nsindex_segment_limit(self):
        idx = NSIndex()
        with self.assert_raises(AssertionError):
            idx[H(1)] = NSIndex.MAX_VALUE + 1, 0, 0, 0
        assert H(1) not in idx
        idx[H(2)] = NSIndex.MAX_VALUE, 0, 0, 0
        assert H(2) in idx


class AllIndexTestCase(BaseTestCase):
    def test_max_load_factor(self):
        assert NSIndex.MAX_LOAD_FACTOR < 1.0
        assert ChunkIndex.MAX_LOAD_FACTOR < 1.0


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
        for y in range(700):  # stay below max load to not trigger resize
            idx[HH(0, y, 0)] = (0, y, 0)

        assert idx.size() == 1031 * 48 + 18  # 1031 buckets + header

        # delete lots of the collisions, creating lots of tombstones
        for y in range(400):  # stay above min load to not trigger resize
            del idx[HH(0, y, 0)]

        # create lots of colliding entries, within the not yet used part of the hashtable
        for y in range(330):  # stay below max load to not trigger resize
            # at y == 259 a resize will happen due to going beyond max EFFECTIVE load
            # if the bug is present, that element will be inserted at the wrong place.
            # and because it will be at the wrong place, it can not be found again.
            idx[HH(600, y, 0)] = 600, y, 0

        # now check if hashtable contents is as expected:

        assert [idx.get(HH(0, y, 0)) for y in range(400, 700)] == [(0, y, 0) for y in range(400, 700)]

        assert [HH(0, y, 0) in idx for y in range(400)] == [False for y in range(400)]  # deleted entries

        # this will fail at HH(600, 259) if the bug is present.
        assert [idx.get(HH(600, y, 0)) for y in range(330)] == [(600, y, 0) for y in range(330)]
