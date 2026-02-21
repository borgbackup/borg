import os

import pytest

from .hashindex_test import H
from .crypto.key_test import TestKey
from ..archive import Statistics
from ..cache import AdHocWithFilesCache, delete_chunkindex_cache, read_chunkindex_from_repo_cache
from ..crypto.key import AESOCBRepoKey
from ..manifest import Manifest
from ..repository import Repository


class TestAdHocWithFilesCache:
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
        return AdHocWithFilesCache(manifest)

    def test_does_not_contain_manifest(self, cache):
        assert not cache.seen_chunk(Manifest.MANIFEST_ID)

    def test_seen_chunk_add_chunk_size(self, cache):
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)

    def test_reuse_after_add_chunk(self, cache):
        assert cache.add_chunk(H(3), {}, b"5678", stats=Statistics()) == (H(3), 4)
        assert cache.reuse_chunk(H(3), 4, Statistics()) == (H(3), 4)

    def test_existing_reuse_after_add_chunk(self, cache):
        assert cache.add_chunk(H(1), {}, b"5678", stats=Statistics()) == (H(1), 4)
        assert cache.reuse_chunk(H(1), 4, Statistics()) == (H(1), 4)

    def test_files_cache(self, cache):
        st = os.stat(".")
        assert cache.file_known_and_unchanged(b"foo", bytes(32), st) == (False, None)
        assert cache.cache_mode == "d"
        assert cache.files == {}


def test_delete_chunkindex_cache_missing(tmp_path):
    """delete_chunkindex_cache handles StoreObjectNotFound when cache entries do not exist."""
    from borgstore.store import ObjectNotFound as StoreObjectNotFound

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # Create a cache entry so list_chunkindex_hashes finds it.
        repository.store_store(f"cache/chunks.{'a' * 64}", b"data")
        # Patch store_delete to raise StoreObjectNotFound (simulates a race or already-deleted entry).
        original_store_delete = repository.store_delete

        def failing_store_delete(name):
            raise StoreObjectNotFound(name)

        repository.store_delete = failing_store_delete
        # Should not raise — the except StoreObjectNotFound catches it.
        delete_chunkindex_cache(repository)
        repository.store_delete = original_store_delete


def test_read_chunkindex_from_repo_cache_missing(tmp_path):
    """read_chunkindex_from_repo_cache handles StoreObjectNotFound when cache does not exist."""
    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # Try to load a non-existent cache entry — should return None, not raise.
        result = read_chunkindex_from_repo_cache(repository, "f" * 64)
        assert result is None
