import os.path

import pytest

from .hashindex import H
from .key import TestKey
from ..archive import Statistics
from ..cache import AdHocCache
from ..crypto.key import AESOCBRepoKey
from ..hashindex import ChunkIndex
from ..manifest import Manifest
from ..repository import Repository


class TestAdHocCache:
    @pytest.fixture
    def repository(self, tmpdir):
        self.repository_location = os.path.join(str(tmpdir), "repository")
        with Repository(self.repository_location, exclusive=True, create=True) as repository:
            repository.put(H(1), b"1234")
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
        cache.chunk_decref(H(1), 1, Statistics())
        assert repository.get(H(1)) == b"1234"

    def test_seen_chunk_add_chunk_size(self, cache):
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)

    def test_deletes_chunks_during_lifetime(self, cache, repository):
        cache.add_chunk(H(5), {}, b"1010", stats=Statistics())
        assert cache.seen_chunk(H(5)) == 1
        cache.chunk_decref(H(5), 1, Statistics())
        assert not cache.seen_chunk(H(5))
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(H(5))

    def test_files_cache(self, cache):
        assert cache.file_known_and_unchanged(b"foo", bytes(32), None) == (False, None)
        assert cache.cache_mode == "d"
        assert cache.files is None

    def test_incref_after_add_chunk(self, cache):
        assert cache.add_chunk(H(3), {}, b"5678", stats=Statistics()) == (H(3), 4)
        assert cache.chunk_incref(H(3), 4, Statistics()) == (H(3), 4)

    def test_existing_incref_after_add_chunk(self, cache):
        """This case occurs with part files, see Archive.chunk_file."""
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)
        assert cache.chunk_incref(H(1), 4, Statistics()) == (H(1), 4)
