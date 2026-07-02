import os
import time

import pytest

from .hashindex_test import H
from .crypto.key_test import TestKey
from ..archive import Statistics
from .. import cache as cache_mod
from ..cache import (
    AdHocWithFilesCache,
    ChunksMixin,
    FileCacheEntry,
    build_chunkindex_from_repo,
    delete_chunkindex_from_repo,
    list_chunkindex_fragments,
    list_chunkindex_hashes,
    read_chunkindex_from_repo,
    repack_chunkindex,
    write_chunkindex_to_repo,
)
from ..hashindex import ChunkIndex, ChunkIndexEntry
from ..crypto.key import AESOCBKey
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
            repository.flush()  # the lone put would stay buffered; make it durable
            yield repository
            repository.flush()  # flush anything a test buffered via the cache before close()

    @pytest.fixture
    def key(self, repository, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = AESOCBKey.create(repository, TestKey.MockArgs())
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


def test_delete_chunkindex_from_repo_missing(tmp_path):
    """delete_chunkindex_from_repo handles StoreObjectNotFound when index entries do not exist."""
    from borgstore.store import ObjectNotFound as StoreObjectNotFound

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # Create an index entry so list_chunkindex_hashes finds it.
        repository.store_store(f"index/{'a' * 64}", b"data")
        # Patch store_delete to raise StoreObjectNotFound (simulates a race or already-deleted entry).
        original_store_delete = repository.store_delete

        def failing_store_delete(name):
            raise StoreObjectNotFound(name)

        repository.store_delete = failing_store_delete
        # Should not raise — the except StoreObjectNotFound catches it.
        delete_chunkindex_from_repo(repository)
        repository.store_delete = original_store_delete


def test_read_chunkindex_from_repo_missing(tmp_path):
    """read_chunkindex_from_repo handles StoreObjectNotFound when the index object does not exist."""
    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # Try to load a non-existent index entry — should return None, not raise.
        result = read_chunkindex_from_repo(repository, "f" * 64)
        assert result is None


def test_chunkindex_cache_not_consolidated_on_access(tmp_path):
    """ChunksMixin.chunks binds the repository index without collapsing the cached fragments.

    Each backup leaves a small incremental index/* fragment; collapsing them all into one
    on every access would re-upload the whole index and, with delete_other, invalidate every other
    client's fragments. Fragment count is reclaimed by `borg compact`, not on every read here.
    """
    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        # seed extra fragments on top of the empty one written at repo creation
        for h in (H(1), H(2)):
            ci = ChunkIndex()
            ci[h] = ChunkIndexEntry(ChunkIndex.F_NEW, 0, h, 0, 4)
            write_chunkindex_to_repo(repository, ci, incremental=False, force_write=True)
        before = len(list_chunkindex_hashes(repository))
        assert before > 1

        cache = ChunksMixin()
        cache.repository = repository
        index = cache.chunks  # binds the repository index; must NOT collapse the fragments

        # fragments are left intact (no consolidation side effect) ...
        assert len(list_chunkindex_hashes(repository)) == before
        # ... and the in-memory index still resolves every seeded chunk
        assert H(1) in index and H(2) in index


def _ci_key(i):
    """A distinct 32-byte chunk id for entry number i."""
    return i.to_bytes(32, "big")


def _make_chunkindex(keys):
    ci = ChunkIndex()
    for k in keys:
        ci[k] = ChunkIndexEntry(ChunkIndex.F_NEW, 0, k, 0, 4)
    return ci


def _seed_fragment(repository, first, count):
    """Write a fresh index fragment holding entries [first, first+count) and return its keys."""
    keys = [_ci_key(i) for i in range(first, first + count)]
    write_chunkindex_to_repo(repository, _make_chunkindex(keys), incremental=False, force_write=True)
    return keys


def test_write_chunkindex_splits_full_write(tmp_path, monkeypatch):
    """A non-incremental (full) write splits the index into fragments of at most MAX entries."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 3000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 1000)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)  # start from a known-empty fragment set
        keys = [_ci_key(i) for i in range(7000)]
        write_chunkindex_to_repo(
            repository, _make_chunkindex(keys), incremental=False, force_write=True, delete_other=True
        )
        frags = list_chunkindex_fragments(repository)
        # 7000 entries split by MAX=3000 -> 3 fragments (3000 + 3000 + 1000)
        counts = sorted(len(read_chunkindex_from_repo(repository, name)) for name, _ in frags)
        assert counts == [1000, 3000, 3000]
        assert all(c <= 3000 for c in counts)


def test_repack_defers_when_below_min_and_few_fragments(tmp_path, monkeypatch):
    """Deferred merging: small fragments summing to < MIN and not exceeding the cap are left alone."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 1000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 3000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_SMALL_FRAGMENT_CAP", 5)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)
        for j in range(3):  # 3 fragments * 100 = 300 entries < MIN, count 3 <= cap 5
            _seed_fragment(repository, j * 100, 100)
        before = {name for name, _ in list_chunkindex_fragments(repository)}
        repack_chunkindex(repository)
        after = {name for name, _ in list_chunkindex_fragments(repository)}
        assert after == before  # nothing merged


def test_repack_seals_when_smalls_reach_min(tmp_path, monkeypatch):
    """When small fragments sum to >= MIN they are merged into a sealed fragment."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 1000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 3000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_SMALL_FRAGMENT_CAP", 100)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)
        all_keys = []
        for j in range(5):  # 5 * 300 = 1500 >= MIN
            all_keys += _seed_fragment(repository, j * 300, 300)
        assert len(list_chunkindex_fragments(repository)) == 5
        repack_chunkindex(repository)
        frags = list_chunkindex_fragments(repository)
        assert len(frags) == 1  # 1500 entries, one fragment (< MAX)
        merged = read_chunkindex_from_repo(repository, frags[0][0])
        assert len(merged) == 1500
        assert set(merged) == set(all_keys)


def test_repack_cap_forces_merge_below_min(tmp_path, monkeypatch):
    """More than SMALL_FRAGMENT_CAP tiny fragments are merged even though they sum to < MIN."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 1000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 3000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_SMALL_FRAGMENT_CAP", 5)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)
        all_keys = []
        for j in range(6):  # 6 * 50 = 300 < MIN, but count 6 > cap 5
            all_keys += _seed_fragment(repository, j * 50, 50)
        assert len(list_chunkindex_fragments(repository)) == 6
        repack_chunkindex(repository)
        frags = list_chunkindex_fragments(repository)
        assert len(frags) == 1  # merged into a single sub-MIN remainder
        merged = read_chunkindex_from_repo(repository, frags[0][0])
        assert len(merged) == 300
        assert set(merged) == set(all_keys)


def test_write_chunkindex_splits_incremental_write(tmp_path, monkeypatch):
    """Even an incremental write (a single backup's new chunks) is split into <= MAX fragments."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 500)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)
        keys = [_ci_key(i) for i in range(1200)]  # all F_NEW -> written by the incremental path
        write_chunkindex_to_repo(repository, _make_chunkindex(keys), incremental=True)
        counts = sorted(
            len(read_chunkindex_from_repo(repository, name)) for name, _ in list_chunkindex_fragments(repository)
        )
        assert counts == [200, 500, 500]  # 1200 split by MAX=500


def test_write_chunkindex_deterministic_fragments(tmp_path, monkeypatch):
    """Identical entry sets always produce identical fragments, regardless of insertion order.

    The write path sorts the keys before partitioning them into batches, so the fragment set
    (content hashes) only depends on the entries, not on the hash table's iteration order.
    This makes writing/repacking idempotent and convergent across clients.
    """
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 500)

    key_ints = list(range(1200))
    hashes = []
    for reverse in (False, True):  # build the same index with different insertion orders
        repository_location = os.fspath(tmp_path / f"repository{reverse}")
        with Repository(repository_location, exclusive=True, create=True) as repository:
            delete_chunkindex_from_repo(repository)
            keys = [_ci_key(i) for i in (reversed(key_ints) if reverse else key_ints)]
            write_chunkindex_to_repo(repository, _make_chunkindex(keys), incremental=False, force_write=True)
            frags = list_chunkindex_fragments(repository)
            hashes.append({name for name, _ in frags})
            # keys are big-endian ints, so sorted key order == numeric order: the batches must
            # hold exactly the ranges [0..499], [500..999], [1000..1199].
            ranges = sorted(sorted(read_chunkindex_from_repo(repository, name)) for name, _ in frags)
            assert ranges == [
                [_ci_key(i) for i in range(0, 500)],
                [_ci_key(i) for i in range(500, 1000)],
                [_ci_key(i) for i in range(1000, 1200)],
            ]
    assert hashes[0] == hashes[1]  # identical fragment sets from differently-ordered inputs


def test_close_consolidates_fragments_across_sessions(tmp_path, monkeypatch):
    """End-to-end: repeated create-like sessions leave a bounded, consolidated set of fragments."""
    monkeypatch.setenv("BORG_PASSPHRASE", "test")
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 200)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 500)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_SMALL_FRAGMENT_CAP", 1000)

    loc = os.fspath(tmp_path / "repository")
    with Repository(loc, exclusive=True, create=True) as repository:
        key = AESOCBKey.create(repository, TestKey.MockArgs())
        Manifest(key, repository).write()

    all_ids = []
    for s in range(5):  # each session adds 100 new chunks (< MIN), so fragments must be consolidated
        with Repository(loc, exclusive=True) as repository:
            manifest = Manifest.load(repository, key=key, operations=Manifest.NO_OPERATION_CHECK)
            cache = AdHocWithFilesCache(manifest)
            try:
                for i in range(s * 100, s * 100 + 100):
                    cid = H(i)
                    all_ids.append(cid)
                    cache.add_chunk(cid, {}, b"data-%d" % i, stats=Statistics())
            finally:
                cache.close()
            repository.flush()

    with Repository(loc, exclusive=True) as repository:
        frags = list_chunkindex_fragments(repository)
        # without repack there would be one incremental fragment per session (plus creation's empty);
        # repack consolidates the small ones as they accumulate, so we end up with fewer.
        assert len(frags) < 5
        assert any(approx >= 200 for _, approx in frags)  # at least one sealed (>= MIN) fragment
        assert all(approx <= 500 + 8 for _, approx in frags)  # none exceeds MAX (+ header slack)
        index = build_chunkindex_from_repo(repository)
        for cid in all_ids:
            assert cid in index


def test_repack_leaves_sealed_untouched_and_reconstructs(tmp_path, monkeypatch):
    """Sealed (>= MIN) fragments survive a repack; build_chunkindex_from_repo reconstructs the index."""
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MIN", 1000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_FRAGMENT_ENTRIES_MAX", 3000)
    monkeypatch.setattr(cache_mod, "CHUNKINDEX_SMALL_FRAGMENT_CAP", 100)

    repository_location = os.fspath(tmp_path / "repository")
    with Repository(repository_location, exclusive=True, create=True) as repository:
        delete_chunkindex_from_repo(repository)
        sealed_keys = _seed_fragment(repository, 0, 2000)  # >= MIN -> sealed
        sealed_hashes = {name for name, _ in list_chunkindex_fragments(repository)}
        assert len(sealed_hashes) == 1
        small_keys = []
        for j in range(3):  # 3 * 400 = 1200 >= MIN -> will be merged
            small_keys += _seed_fragment(repository, 2000 + j * 400, 400)

        repack_chunkindex(repository)

        frags = {name for name, _ in list_chunkindex_fragments(repository)}
        assert sealed_hashes <= frags  # the sealed fragment was not rewritten or deleted
        assert len(frags) == 2  # sealed one + the merged small ones

        index = build_chunkindex_from_repo(repository)
        assert len(index) == 2000 + 1200
        assert set(index) == set(sealed_keys + small_keys)
