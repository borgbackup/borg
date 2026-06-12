import os
import time

import pytest

from .hashindex_test import H
from .crypto.key_test import TestKey
from ..archive import Statistics
from ..cache import AdHocWithFilesCache, FileCacheEntry, delete_chunkindex_cache, read_chunkindex_from_repo_cache
from ..crypto.key import AESOCBRepoKey
from ..helpers import safe_ns
from ..helpers.msgpack import int_to_timestamp
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

    def test_no_change_backup_keeps_files_cache(self, repository, key, manifest):
        # Regression test for #9749: a backup that does not chunk any new file leaves
        # _newest_cmtime unset. The writer must treat "unset" as "keep everything" and
        # must NOT discard the current (age == 0) entries with an epoch cutoff.
        # "cis" == normalized form of the "borg create" default "ctime,size,inode"
        cache = AdHocWithFilesCache(manifest, cache_mode="cis", archive_name="test")
        # the chunk that our cached file references (needed so the entry can be (de)compressed):
        cache.add_chunk(H(5), {}, b"5678", stats=Statistics())
        # a "current" files cache entry as left behind by a no-change backup: the file was found
        # unchanged (so its age was reset to 0), but nothing got chunked, so memorize_file() was
        # never called and _newest_cmtime stayed at its initial value.
        now_ns = safe_ns(time.time_ns())
        entry = FileCacheEntry(
            age=0, inode=1, size=4, ctime=int_to_timestamp(now_ns), mtime=int_to_timestamp(now_ns), chunks=[(H(5), 4)]
        )
        path_hash = H(42)
        files = {path_hash: cache.compress_entry(entry)}
        assert cache._newest_cmtime is None  # nothing was chunked in this backup
        integrity_data = cache._write_files_cache(files)
        cache.cache_config.integrity[cache.files_cache_name()] = integrity_data
        # with the bug (initial value 0 instead of None) the cutoff would be the epoch and the
        # entry would be dropped; after the fix the entry must still be there:
        loaded = cache._read_files_cache()
        assert path_hash in loaded


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


def test_chunkindex_cache_consolidated_on_access(tmp_path):
    """ChunksMixin.chunks collapses multiple cached chunk-index fragments into a single one.

    Without consolidation every backup's incremental save would leave another cache/chunks.*
    behind for the next run to merge, so the fragments would grow without bound.
    """
    from ..cache import ChunksMixin, write_chunkindex_to_repo_cache, list_chunkindex_hashes
    from ..hashindex import ChunkIndex, ChunkIndexEntry

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # seed extra fragments on top of the empty one written at repo creation
        for h in (H(1), H(2)):
            ci = ChunkIndex()
            ci[h] = ChunkIndexEntry(ChunkIndex.F_NEW, 0, h, 0, 4)
            write_chunkindex_to_repo_cache(repository, ci, incremental=False, force_write=True)
        assert len(list_chunkindex_hashes(repository)) > 1

        cache = ChunksMixin()
        cache.repository = repository
        index = cache.chunks  # binds the repository index and consolidates the fragments

        assert len(list_chunkindex_hashes(repository)) == 1
        assert H(1) in index and H(2) in index
