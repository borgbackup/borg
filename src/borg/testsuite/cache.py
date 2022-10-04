import io
import os.path

from ..helpers.msgpack import packb

import pytest

from .hashindex import H
from .key import TestKey
from ..archive import Statistics
from ..cache import AdHocCache
from ..crypto.key import AESOCBRepoKey
from ..hashindex import ChunkIndex, CacheSynchronizer
from ..manifest import Manifest
from ..repository import Repository


class TestCacheSynchronizer:
    @pytest.fixture
    def index(self):
        return ChunkIndex()

    @pytest.fixture
    def sync(self, index):
        return CacheSynchronizer(index)

    def test_no_chunks(self, index, sync):
        data = packb({"foo": "bar", "baz": 1234, "bar": 5678, "user": "chunks", "chunks": []})
        sync.feed(data)
        assert not len(index)

    def test_simple(self, index, sync):
        data = packb({"foo": "bar", "baz": 1234, "bar": 5678, "user": "chunks", "chunks": [(H(1), 1), (H(2), 2)]})
        sync.feed(data)
        assert len(index) == 2
        assert index[H(1)] == (1, 1)
        assert index[H(2)] == (1, 2)

    def test_multiple(self, index, sync):
        data = packb({"foo": "bar", "baz": 1234, "bar": 5678, "user": "chunks", "chunks": [(H(1), 1), (H(2), 2)]})
        data += packb({"xattrs": {"security.foo": "bar", "chunks": "123456"}, "stuff": [(1, 2, 3)]})
        data += packb(
            {
                "xattrs": {"security.foo": "bar", "chunks": "123456"},
                "chunks": [(H(1), 1), (H(2), 2)],
                "stuff": [(1, 2, 3)],
            }
        )
        data += packb({"chunks": [(H(3), 1)]})
        data += packb({"chunks": [(H(1), 1)]})

        part1 = data[:70]
        part2 = data[70:120]
        part3 = data[120:]
        sync.feed(part1)
        sync.feed(part2)
        sync.feed(part3)
        assert len(index) == 3
        assert index[H(1)] == (3, 1)
        assert index[H(2)] == (2, 2)
        assert index[H(3)] == (1, 1)

    @pytest.mark.parametrize(
        "elem,error",
        (
            ({1: 2}, "Unexpected object: map"),
            (
                bytes(213),
                ["Unexpected bytes in chunks structure", "Incorrect key length"],  # structure 2/3
            ),  # structure 3/3
            (1, "Unexpected object: integer"),
            (1.0, "Unexpected object: double"),
            (True, "Unexpected object: true"),
            (False, "Unexpected object: false"),
            (None, "Unexpected object: nil"),
        ),
    )
    @pytest.mark.parametrize(
        "structure",
        (lambda elem: {"chunks": elem}, lambda elem: {"chunks": [elem]}, lambda elem: {"chunks": [(elem, 1)]}),
    )
    def test_corrupted(self, sync, structure, elem, error):
        packed = packb(structure(elem))
        with pytest.raises(ValueError) as excinfo:
            sync.feed(packed)
        if isinstance(error, str):
            error = [error]
        possible_errors = ["cache_sync_feed failed: " + error for error in error]
        assert str(excinfo.value) in possible_errors

    @pytest.mark.parametrize(
        "data,error",
        (
            # Incorrect tuple length
            ({"chunks": [(bytes(32), 2, 3, 4)]}, "Invalid chunk list entry length"),
            ({"chunks": [(bytes(32),)]}, "Invalid chunk list entry length"),
            # Incorrect types
            ({"chunks": [(1, 2)]}, "Unexpected object: integer"),
            ({"chunks": [(1, bytes(32))]}, "Unexpected object: integer"),
            ({"chunks": [(bytes(32), 1.0)]}, "Unexpected object: double"),
        ),
    )
    def test_corrupted_ancillary(self, index, sync, data, error):
        packed = packb(data)
        with pytest.raises(ValueError) as excinfo:
            sync.feed(packed)
        assert str(excinfo.value) == "cache_sync_feed failed: " + error

    def make_index_with_refcount(self, refcount):
        index_data = io.BytesIO()
        index_data.write(b"BORG2IDX")
        # version
        index_data.write((2).to_bytes(4, "little"))
        # num_entries
        index_data.write((1).to_bytes(4, "little"))
        # num_buckets
        index_data.write((1).to_bytes(4, "little"))
        # num_empty
        index_data.write((0).to_bytes(4, "little"))
        # key_size
        index_data.write((32).to_bytes(4, "little"))
        # value_size
        index_data.write((3 * 4).to_bytes(4, "little"))
        # reserved
        index_data.write(bytes(1024 - 32))

        index_data.write(H(0))
        index_data.write(refcount.to_bytes(4, "little"))
        index_data.write((1234).to_bytes(4, "little"))
        index_data.write((5678).to_bytes(4, "little"))

        index_data.seek(0)
        index = ChunkIndex.read(index_data)
        return index

    def test_corrupted_refcount(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE + 1)
        sync = CacheSynchronizer(index)
        data = packb({"chunks": [(H(0), 1)]})
        with pytest.raises(ValueError) as excinfo:
            sync.feed(data)
        assert str(excinfo.value) == "cache_sync_feed failed: invalid reference count"

    def test_refcount_max_value(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE)
        sync = CacheSynchronizer(index)
        data = packb({"chunks": [(H(0), 1)]})
        sync.feed(data)
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234)

    def test_refcount_one_below_max_value(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE - 1)
        sync = CacheSynchronizer(index)
        data = packb({"chunks": [(H(0), 1)]})
        sync.feed(data)
        # Incremented to maximum
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234)
        sync.feed(data)
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234)


class TestAdHocCache:
    @pytest.fixture
    def repository(self, tmpdir):
        self.repository_location = os.path.join(str(tmpdir), "repository")
        with Repository(self.repository_location, exclusive=True, create=True) as repository:
            repository.put(H(1), b"1234")
            repository.put(Manifest.MANIFEST_ID, b"5678")
            yield repository

    @pytest.fixture
    def key(self, repository, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = AESOCBRepoKey.create(repository, TestKey.MockArgs())
        return key

    @pytest.fixture
    def manifest(self, repository, key):
        Manifest(key, repository).write()
        return Manifest.load(repository, key=key, operations=Manifest.NO_OPERATION_CHECK)

    @pytest.fixture
    def cache(self, repository, key, manifest):
        return AdHocCache(manifest)

    def test_does_not_contain_manifest(self, cache):
        assert not cache.seen_chunk(Manifest.MANIFEST_ID)

    def test_does_not_delete_existing_chunks(self, repository, cache):
        assert cache.seen_chunk(H(1)) == ChunkIndex.MAX_VALUE
        cache.chunk_decref(H(1), Statistics())
        assert repository.get(H(1)) == b"1234"

    def test_does_not_overwrite(self, cache):
        with pytest.raises(AssertionError):
            cache.add_chunk(H(1), {}, b"5678", stats=Statistics(), overwrite=True)

    def test_seen_chunk_add_chunk_size(self, cache):
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)

    def test_deletes_chunks_during_lifetime(self, cache, repository):
        """E.g. checkpoint archives"""
        cache.add_chunk(H(5), {}, b"1010", stats=Statistics())
        assert cache.seen_chunk(H(5)) == 1
        cache.chunk_decref(H(5), Statistics())
        assert not cache.seen_chunk(H(5))
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(H(5))

    def test_files_cache(self, cache):
        assert cache.file_known_and_unchanged(b"foo", bytes(32), None) == (False, None)
        assert cache.cache_mode == "d"
        assert cache.files is None

    def test_txn(self, cache):
        assert not cache._txn_active
        cache.seen_chunk(H(5))
        assert cache._txn_active
        assert cache.chunks
        cache.rollback()
        assert not cache._txn_active
        assert not hasattr(cache, "chunks")

    def test_incref_after_add_chunk(self, cache):
        assert cache.add_chunk(H(3), {}, b"5678", stats=Statistics()) == (H(3), 4)
        assert cache.chunk_incref(H(3), Statistics()) == (H(3), 4)

    def test_existing_incref_after_add_chunk(self, cache):
        """This case occurs with part files, see Archive.chunk_file."""
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)
        assert cache.chunk_incref(H(1), Statistics()) == (H(1), 4)
