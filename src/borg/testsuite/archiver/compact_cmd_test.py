import os
from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...helpers import get_cache_dir, bin_to_hex, sig_int, Error
from ...hashindex import ChunkIndex
from ...repository import Repository
from ...cache import files_cache_name, discover_files_cache_names, list_chunkindex_hashes
from ...cache import delete_chunkindex_from_repo, write_chunkindex_to_repo
from ...manifest import Manifest
from ...archive import Archive
from ...archiver.compact_cmd import ArchiveGarbageCollector
from . import cmd, create_regular_file, create_src_archive, generate_archiver_tests, open_repository, RK_ENCRYPTION
from . import changedir
from ..repository_test import H, fchunk, pdchunk

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


@pytest.mark.parametrize("stats", (True, False))
def test_compact_empty_repository(archivers, request, stats):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)

    args = ("-v", "--stats") if stats else ("-v",)
    output = cmd(archiver, "compact", *args, exit_code=0)
    assert "Starting compaction" in output
    if stats:
        assert "Repository size is 0 B in 0 objects." in output
    else:
        assert "Repository size is" not in output
        assert "Repository has data stored in" not in output
    assert "Finished compaction" in output


@pytest.mark.parametrize("stats", (True, False))
def test_compact_after_deleting_all_archives(archivers, request, stats):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    cmd(archiver, "delete", "-a", "archive", exit_code=0)

    args = ("-v", "--stats") if stats else ("-v",)
    output = cmd(archiver, "compact", *args, exit_code=0)
    assert "Starting compaction" in output
    assert "Deleting " in output
    if stats:
        assert "Repository size is 0 B in 0 objects." in output
    else:
        assert "Repository size is" not in output
        assert "Repository has data stored in" not in output
    assert "Finished compaction" in output


@pytest.mark.parametrize("stats", (True, False))
def test_compact_after_deleting_some_archives(archivers, request, stats):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive1")
    create_src_archive(archiver, "archive2")
    cmd(archiver, "delete", "-a", "archive1", exit_code=0)

    args = ("-v", "--stats") if stats else ("-v",)
    output = cmd(archiver, "compact", *args, exit_code=0)
    assert "Starting compaction" in output
    assert "Deleting " in output
    if stats:
        assert "Repository size is 0 B in 0 objects." not in output
    else:
        assert "Repository size is" not in output
        assert "Repository has data stored in" not in output
    assert "Finished compaction" in output


def test_compact_index_corruption(archivers, request):
    # see issue #8813 (borg did not write a complete index)
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive1")

    output = cmd(archiver, "compact", "-v", "--stats", exit_code=0)
    assert "missing objects" not in output

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "missing objects" not in output

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "missing objects" not in output

    output = cmd(archiver, "compact", "-v", "--stats", exit_code=0)
    assert "missing objects" not in output


@pytest.mark.parametrize("stats", (True, False))
def test_compact_interrupted_does_not_poison_chunk_index(archivers, request, monkeypatch, stats):
    """Regression test for issue #9748.

    If a compact is interrupted after it deleted repository objects but before it wrote the
    updated chunk index, the still-existing index/* must not claim that the deleted
    objects are still present. Otherwise a later "borg create" trusts the stale index, does
    not re-upload the affected chunks and silently produces an archive with dangling object
    references (which extracts to zero bytes).

    The fix invalidates all chunk indexes before the first delete, so an interruption
    is conservative: the next client rebuilds the index from actual repository contents and
    re-uploads any deleted data. This is tested for both compact paths (default and --stats).
    """

    archiver = request.getfixturevalue(archivers)

    # Unique content, so the chunk(s) become unused once we delete the only archive referencing them.
    content = os.urandom(1024 * 1024)
    create_regular_file(archiver.input_path, "file1", contents=content)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    cmd(archiver, "delete", "-a", "archive1")

    # Simulate an interruption inside compact: run the real garbage collection (which deletes the
    # unused objects), but force it to abort right before it writes the fresh, updated chunk index.
    repository = open_repository(archiver)
    with repository:
        manifest = Manifest.load(repository, (Manifest.Operation.DELETE,))
        gc = ArchiveGarbageCollector(repository, manifest, stats=stats, iec=False, threshold=40.0)

        def interrupt():
            raise KeyboardInterrupt("simulated interruption before save_chunk_index")

        monkeypatch.setattr(gc, "save_chunk_index", interrupt)
        with pytest.raises(KeyboardInterrupt):
            gc.garbage_collect()

    # The objects were deleted, so no readable chunk index may still list them.
    repository = open_repository(archiver)
    with repository:
        assert list_chunkindex_hashes(repository) == []

    # A later backup of identical content must re-upload the deleted chunks, ...
    cmd(archiver, "create", "archive2", "input")
    # ... and extracting it must reproduce the original bytes without missing-object warnings.
    with changedir("output"):
        output = cmd(archiver, "extract", "archive2")
        assert "missing" not in output
        with open(os.path.join("input", "file1"), "rb") as fd:
            assert fd.read() == content


def test_compact_soft_interrupt_persists_valid_index(archivers, request, monkeypatch):
    """One Ctrl-C during pack deletion stops at the next pack boundary, saves a chunk index that
    still matches the repository, and exits with an error (#9830). A later compact finishes the rest."""
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    archiver = request.getfixturevalue(archivers)
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "1")  # one object per pack -> several packs to stop between

    for i in range(3):
        create_regular_file(archiver.input_path, f"file{i}", contents=os.urandom(1024))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive", "input")
    cmd(archiver, "delete", "-a", "archive")

    repository = open_repository(archiver)
    with repository:
        pack_names_before = {info.name for info in repository.store_list("packs")}
        assert len(pack_names_before) >= 2  # need several packs to observe an early stop

        manifest = Manifest.load(repository, (Manifest.Operation.DELETE,))
        gc = ArchiveGarbageCollector(repository, manifest, stats=False, iec=False, threshold=10)

        original_store_delete = repository.store_delete
        calls = []

        def store_delete_then_interrupt(name, **kwargs):
            original_store_delete(name, **kwargs)
            if name.startswith("packs/"):  # only real pack deletes, not the earlier archive/index deletes
                calls.append(name)
                if len(calls) == 1:
                    sig_int._sig_int_triggered = True  # one Ctrl-C after the first pack is deleted

        monkeypatch.setattr(repository, "store_delete", store_delete_then_interrupt)
        try:
            with pytest.raises(Error, match="Got Ctrl-C"):
                gc.garbage_collect()
        finally:
            sig_int._sig_int_triggered = False  # reset the global flag for the following tests

    # every persisted index entry points at a pack that still exists
    repository = open_repository(archiver)
    with repository:
        assert list_chunkindex_hashes(repository) != []
        pack_names_after = {info.name for info in repository.store_list("packs")}
        assert 0 < len(pack_names_after) < len(pack_names_before)  # some packs deleted, some left
        for id, entry in repository.chunks.iteritems():
            assert bin_to_hex(entry.pack_id) in pack_names_after

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Finished compaction" in output


def test_compact_packs_respects_threshold(tmp_path):
    # Two multi-object packs in one repo, then pack-level compaction at a 40% threshold. The pack that
    # wastes 2/3 of its bytes is rewritten down to its single kept object (and its old file deleted); the
    # pack that wastes only 1/3 stays untouched, since copying its kept objects to reclaim that little is
    # not worth it. This covers the rewrite, leave-alone and keep/drop split unique to multi-object packs.

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4  # buffer several objects, so each flush() writes one pack
        for i in range(3):  # H0..H2 -> wasteful pack
            repository.put(H(i), fchunk(f"DATA{i}".encode(), chunk_id=H(i)))
        repository.flush()
        for i in range(3, 6):  # H3..H5 -> frugal pack
            repository.put(H(i), fchunk(f"DATA{i}".encode(), chunk_id=H(i)))
        repository.flush()

        wasteful_pack = repository.chunks[H(0)].pack_id
        frugal_pack = repository.chunks[H(3)].pack_id
        # wasteful pack keeps only H0 (2/3 wasted), frugal pack keeps H3 and H4 (1/3 wasted)
        used = {H(0), H(3), H(4)}
        for i in range(6):
            entry = repository.chunks[H(i)]
            flags = ChunkIndex.F_USED if H(i) in used else ChunkIndex.F_NONE
            repository.chunks[H(i)] = entry._replace(flags=flags)

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=40)
        gc.chunks = repository.chunks
        gc.compact_packs()

        # wasteful pack was rewritten: the kept object reads back, the dropped objects and the old file are gone
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert repository.get(H(1), raise_missing=False) is None
        assert repository.get(H(2), raise_missing=False) is None
        # frugal pack stayed below threshold: untouched, every object (even the unused H5) still present
        for i in range(3, 6):
            assert pdchunk(repository.get(H(i))) == f"DATA{i}".encode()
        pack_names = [info.name for info in repository.store_list("packs")]
        assert bin_to_hex(wasteful_pack) not in pack_names
        assert bin_to_hex(frugal_pack) in pack_names


def test_compact_superseded_duplicate(tmp_path):
    # Issue #9868 repro. Concurrent backups can write the same chunk into two packs; when the index
    # fragments merge, only one copy stays indexed and the other is left as unindexed bytes in a pack.
    # Rewriting such a pack (because of its ordinary unused objects) reclaims those superseded bytes:
    # the surviving copy is authoritative, so the duplicate is dropped.
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4  # one flush() -> one pack
        # pack A: three objects W, X, Y (X will be the one later superseded by a copy in pack B)
        for cid, data in [(H(0), b"WWWW"), (H(1), b"XXXX"), (H(2), b"YYYY")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        pack_a = repository.chunks[H(0)].pack_id
        pack_a_size = next(i.size for i in repository.store_list("packs") if i.name == bin_to_hex(pack_a))
        x_size = repository.chunks[H(1)].obj_size  # X's copy in pack A becomes a superseded gap
        y_size = repository.chunks[H(2)].obj_size

        # pack B: a second copy of X only, in its own pack (as a concurrent writer would have produced).
        repository.put(H(1), fchunk(b"XXXX", chunk_id=H(1)))
        repository.flush()
        pack_b = repository.chunks[H(1)].pack_id
        assert pack_b != pack_a
        # after the (simulated) fragment merge, the index points X at pack B; pack A's X bytes are now
        # a superseded, unindexed span. put() already repointed the index to pack B, so nothing to do.

        # mark usage: W and X used, Y unused. pack A is now mixed (W used, X superseded gap, Y unused).
        used = {H(0), H(1)}
        for i in range(3):
            entry = repository.chunks[H(i)]
            flags = ChunkIndex.F_USED if H(i) in used else ChunkIndex.F_NONE
            repository.chunks[H(i)] = entry._replace(flags=flags)

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        # W still readable; X still readable from pack B; Y (the unused indexed object) dropped.
        assert pdchunk(repository.get(H(0))) == b"WWWW"
        assert pdchunk(repository.get(H(1))) == b"XXXX"
        assert repository.get(H(2), raise_missing=False) is None
        # pack A rewritten, shrunk by Y's bytes (unused indexed) plus X's superseded gap: only W remains.
        assert bin_to_hex(pack_a) not in [info.name for info in repository.store_list("packs")]
        new_pack = repository.chunks[H(0)].pack_id
        new_size = next(i.size for i in repository.store_list("packs") if i.name == bin_to_hex(new_pack))
        assert new_size == pack_a_size - y_size - x_size


def test_compact_keeps_orphan_pack(tmp_path):
    # A pack with no index entries at all (a backup that crashed after writing the pack but before
    # writing its index) is left alone: its objects hold no reclaimable indexed waste and may be live
    # data, so dropping them is "borg check --repair"'s call, not compact's (#9868).
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4
        repository.put(H(0), fchunk(b"KEEP", chunk_id=H(0)))
        repository.flush()
        live_pack = repository.chunks[H(0)].pack_id
        repository.chunks[H(0)] = repository.chunks[H(0)]._replace(flags=ChunkIndex.F_USED)

        # write an extra pack directly to the store, with NO chunk-index entry for it.
        orphan_key = "packs/" + "ab" * 32
        repository.store_store(orphan_key, b"orphan pack bytes")
        assert "ab" * 32 in [info.name for info in repository.store_list("packs")]

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        pack_names = [info.name for info in repository.store_list("packs")]
        assert "ab" * 32 in pack_names  # orphan pack kept for check --repair
        assert bin_to_hex(live_pack) in pack_names  # the used pack kept
        assert pdchunk(repository.get(H(0))) == b"KEEP"


def test_compact_keeps_unindexed_waste(tmp_path):
    # A pack whose indexed objects are all used, but which also holds unindexed bytes, is left alone:
    # compact reclaims only indexed-but-unused bytes, never bytes no index entry covers. Those may be
    # live data for "borg check --repair" (#9868). Delete one object's index entry to make a big
    # unindexed span; compact must not rewrite the pack over it.
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4
        for cid, data in [(H(0), b"AAAA"), (H(1), b"BBBBBBBBBB"), (H(2), b"CCCC")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        pack = repository.chunks[H(0)].pack_id
        # every remaining indexed object is used ...
        for i in (0, 2):
            repository.chunks[H(i)] = repository.chunks[H(i)]._replace(flags=ChunkIndex.F_USED)
        # ... but H(1)'s big object becomes an unindexed superseded span (well over threshold if counted).
        del repository.chunks[H(1)]

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        assert repository.chunks[H(0)].pack_id == pack  # not rewritten: unindexed bytes are not reclaimed
        assert bin_to_hex(pack) in [info.name for info in repository.store_list("packs")]
        assert pdchunk(repository.get(H(0))) == b"AAAA"
        assert pdchunk(repository.get(H(2))) == b"CCCC"


def test_compact_reclaims_indexed_waste_only(tmp_path):
    # compact reclaims a pack's indexed-but-unused bytes, but leaves alone a pack whose only waste is
    # unindexed (bytes no index entry covers): those may be live data "borg check --repair" can
    # recover (#9868).
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4
        # indexed-waste pack: one used, one unused object -> reclaimable waste, every byte still indexed.
        for cid, data in [(H(0), b"KEEP"), (H(1), b"DROPME")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        waste_pack = repository.chunks[H(0)].pack_id
        repository.chunks[H(0)] = repository.chunks[H(0)]._replace(flags=ChunkIndex.F_USED)
        repository.chunks[H(1)] = repository.chunks[H(1)]._replace(flags=ChunkIndex.F_NONE)  # unused waste

        # unindexed-waste pack: one used object plus unindexed bytes (H(3)'s entry dropped from the index).
        for cid, data in [(H(2), b"LIVE"), (H(3), b"UNINDEXED")]:
            repository.put(cid, fchunk(data, chunk_id=cid))
        repository.flush()
        unindexed_pack = repository.chunks[H(2)].pack_id
        repository.chunks[H(2)] = repository.chunks[H(2)]._replace(flags=ChunkIndex.F_USED)
        del repository.chunks[H(3)]  # its bytes remain in unindexed_pack as unindexed data

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        pack_names = [info.name for info in repository.store_list("packs")]
        # indexed waste -> compacted, kept object still readable
        assert bin_to_hex(waste_pack) not in pack_names
        assert pdchunk(repository.get(H(0))) == b"KEEP"
        # only unindexed waste -> left untouched for check --repair
        assert bin_to_hex(unindexed_pack) in pack_names
        assert pdchunk(repository.get(H(2))) == b"LIVE"


def test_compact_keeps_undelete_data_when_chunks_missing(archivers, request):
    # On a damaged repo, compact preserves soft-deleted archives whole (metadata and data), so
    # "borg undelete" can still recover them until "borg check --repair" has run (#9868).
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # two archives with distinct content, so the soft-deleted one has its own chunks to preserve.
    create_regular_file(archiver.input_path, "kept_dir/kept_file", contents=b"K" * (1024 * 80))
    create_regular_file(archiver.input_path, "gone_dir/gone_file", contents=b"G" * (1024 * 80))
    cmd(archiver, "create", "kept", "input/kept_dir")
    cmd(archiver, "create", "gone", "input/gone_dir")
    cmd(archiver, "delete", "gone")  # soft-delete: finalized only once compact nukes it

    # damage the repo: drop a content chunk index entry of the live "kept" archive, so compact
    # sees a missing object and treats the repo as damaged.
    repository = open_repository(archiver)
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        kept = Archive(manifest, manifest.archives.get_one(["kept"]).id)
        victim = next(id for item in kept.iter_items() if "chunks" in item for id, _ in item.chunks)
        del repository.chunks[victim]
        write_chunkindex_to_repo(repository, repository.chunks, incremental=False, force_write=True, delete_other=True)

    output = cmd(archiver, "compact", "-v", exit_code=EXIT_ERROR)
    assert "missing objects" in output  # the repo is seen as damaged ...
    assert "Cleaning archives directory" not in output  # ... so soft-deleted archives are not nuked

    cmd(archiver, "undelete", "gone")  # recover the soft-deleted archive
    with changedir("output"):
        cmd(archiver, "extract", "gone")
    with open("output/input/gone_dir/gone_file", "rb") as fd:
        assert fd.read() == b"G" * (1024 * 80)  # its data survived compaction


def test_compact_keeps_stale_index_entries(tmp_path):
    # An index entry whose pack file is gone from the store is stale, but it may be an archive's only
    # pointer to a chunk: compact keeps it and only reports the problem, since dropping it is
    # "borg check --repair"'s call. A used stale entry means data is missing (#9850).
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4
        repository.put(H(0), fchunk(b"GONE", chunk_id=H(0)))
        repository.flush()
        gone_pack = repository.chunks[H(0)].pack_id
        repository.chunks[H(0)] = repository.chunks[H(0)]._replace(flags=ChunkIndex.F_USED)
        repository.store_delete("packs/" + bin_to_hex(gone_pack))  # delete the pack file the index still references

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        assert H(0) in repository.chunks  # stale entry kept for check --repair, not dropped


def test_compact_skips_oversized_index_entry(tmp_path):
    # An index entry claiming more bytes than its pack file holds means index corruption: compact must
    # leave the pack untouched rather than rewrite it from a bad size (#9868).
    from ...archiver.compact_cmd import ArchiveGarbageCollector

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        repository._pack_writer.max_count = 4
        repository.put(H(0), fchunk(b"DATA", chunk_id=H(0)))
        repository.flush()
        pack = repository.chunks[H(0)].pack_id
        entry = repository.chunks[H(0)]
        repository.chunks[H(0)] = entry._replace(flags=ChunkIndex.F_USED, obj_size=entry.obj_size + 10000)

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()

        assert bin_to_hex(pack) in [info.name for info in repository.store_list("packs")]  # left untouched
        assert pdchunk(repository.get(H(0))) == b"DATA"


def test_compact_packs_merges_tiny_packs(tmp_path, monkeypatch):
    # Incremental backups leave many tiny, fully-used packs behind (issue #9816): the current
    # unused-bytes policy never touches them, so they pile up. Once their combined size reaches a
    # full pack, compact merges them into fewer, larger packs while keeping every object readable.
    # BORG_PACK_MAX_SIZE is set small here so a handful of tiny packs already cross that threshold.
    monkeypatch.setenv("BORG_PACK_MAX_SIZE", "300")

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        num = 10
        for i in range(num):
            repository.put(H(i), fchunk(f"DATA{i}".encode(), chunk_id=H(i)))
            repository.flush()  # flush after each put -> one object per pack -> many tiny packs

        # mark every object used, so no pack qualifies for drop/rewrite; they only qualify for merging
        for i in range(num):
            entry = repository.chunks[H(i)]
            repository.chunks[H(i)] = entry._replace(flags=ChunkIndex.F_USED)

        packs_before = {info.name for info in repository.store_list("packs")}
        assert len(packs_before) == num  # one tiny pack per object
        total_bytes = sum(repository.store.info("packs/" + name).size for name in packs_before)
        assert total_bytes >= repository.pack_max_size  # combined size crosses the merge threshold

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()
        assert gc.store_changed is True  # the merge changed the store

        # the tiny packs collapse into fewer, larger packs (each up to pack_max_size)
        packs_after = {info.name for info in repository.store_list("packs")}
        assert len(packs_after) < len(packs_before)
        assert packs_after - packs_before  # at least one genuinely new merged pack
        # every object still reads back correctly from wherever it now lives
        for i in range(num):
            assert pdchunk(repository.get(H(i))) == f"DATA{i}".encode()
        # the (rebuilt) chunk index only references packs that still exist
        for id, entry in repository.chunks.iteritems():
            assert bin_to_hex(entry.pack_id) in packs_after

        # a merged full-size pack is no longer tiny (the tiny limit is pack_max_size // 2 here), so a
        # second compact finds nothing to merge and leaves the store unchanged.
        gc2 = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc2.chunks = repository.chunks
        gc2.compact_packs()
        assert gc2.store_changed is False
        assert {info.name for info in repository.store_list("packs")} == packs_after


def test_compact_packs_below_merge_size_gate_leaves_tiny_packs(tmp_path, monkeypatch):
    # Guards against the count-based trigger this replaced (#9816 review feedback): merging must not
    # fire just because several tiny packs exist, only once their combined size could produce a full
    # pack. Otherwise a small repack would invalidate the chunk index for every client for no lasting
    # reduction in tiny-pack count (Thomas's "10 packs of 1 kB merge into a still-tiny 10 kB pack"
    # scenario).
    monkeypatch.setenv("BORG_PACK_MAX_SIZE", "100000")  # far above what these tiny packs total

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        for i in range(3):
            repository.put(H(i), fchunk(f"DATA{i}".encode(), chunk_id=H(i)))
            repository.flush()
        for i in range(3):
            entry = repository.chunks[H(i)]
            repository.chunks[H(i)] = entry._replace(flags=ChunkIndex.F_USED)

        packs_before = {info.name for info in repository.store_list("packs")}
        assert len(packs_before) == 3

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()
        assert gc.store_changed is False  # combined tiny bytes stay far below one full pack: leave them alone

        assert {info.name for info in repository.store_list("packs")} == packs_before


def test_compact_packs_below_all_packs_gate_changes_nothing(tmp_path):
    # A tiny unused pack alongside a large used one: reclaiming it would free far less than the
    # all-packs threshold (threshold/5, i.e. 2% at the default). Any compaction forces a full
    # chunk-index rewrite that invalidates every client's cached index (#9817), so below the gate
    # compact must leave the repo untouched rather than pay that cost for so little.

    location = os.fspath(tmp_path / "repo")
    with Repository(location, exclusive=True, create=True) as repository:
        # one big, fully-used pack (well above MIN_PACK_SIZE, so it is not a merge candidate) ...
        repository.put(H(0), fchunk(b"U" * 2_000_000, chunk_id=H(0)))
        repository.flush()
        # ... and one tiny pack we would otherwise drop entirely (all its bytes unused)
        repository.put(H(1), fchunk(b"x", chunk_id=H(1)))
        repository.flush()

        repository.chunks[H(0)] = repository.chunks[H(0)]._replace(flags=ChunkIndex.F_USED)
        repository.chunks[H(1)] = repository.chunks[H(1)]._replace(flags=ChunkIndex.F_NONE)

        packs_before = {info.name for info in repository.store_list("packs")}
        assert len(packs_before) == 2

        gc = ArchiveGarbageCollector(repository, manifest=None, stats=False, iec=False, threshold=10)
        gc.chunks = repository.chunks
        gc.compact_packs()
        assert gc.store_changed is False  # below the all-packs gate: nothing was touched

        # both packs (including the fully-unused tiny one) still exist, and both objects read back
        assert {info.name for info in repository.store_list("packs")} == packs_before
        assert pdchunk(repository.get(H(0))) == b"U" * 2_000_000
        assert pdchunk(repository.get(H(1))) == b"x"


def test_compact_gc_after_index_loss(archivers, request):
    """When no chunk index exists (e.g. after an interrupted compact, #9748), compact
    rebuilds the index from the packs. The rebuilt entries must start unused (init_flags=F_NONE),
    otherwise every object looks used and this compact run frees nothing."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    cmd(archiver, "delete", "-a", "archive")

    # drop all chunk indexes, like an interrupted compact leaves the repo
    repository = open_repository(archiver)
    with repository:
        delete_chunkindex_from_repo(repository)

    output = cmd(archiver, "compact", "-v", "--stats", exit_code=0)
    assert "Repository size is 0 B in 0 objects." in output


def test_compact_pack_rewrite_updates_persisted_index(archivers, request, monkeypatch):
    """Regression test for issue #9850.

    When compact rewrites a mixed pack (still-used objects are copied into a new pack, the old
    pack is deleted), the persisted chunk index must point at the new pack. A stale index makes
    extract fail on the kept chunks and makes the next delete + compact crash with ObjectNotFound
    when it tries to delete the already gone old pack.
    """
    archiver = request.getfixturevalue(archivers)
    # one big pack per create run: all of archive1's chunks land in a single pack, so that pack
    # is mixed (used + unused objects) once archive1 is deleted below.
    monkeypatch.setenv("BORG_PACK_MAX_COUNT", "1000")

    contents_kept = os.urandom(1024)  # unique contents -> own chunk
    contents_dropped = os.urandom(1024)
    create_regular_file(archiver.input_path, "file_kept", contents=contents_kept)
    create_regular_file(archiver.input_path, "file_dropped", contents=contents_dropped)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    # archive2 references only file_kept's chunk, which deduplicates against archive1's pack.
    os.remove(os.path.join(archiver.input_path, "file_dropped"))
    cmd(archiver, "create", "archive2", "input")

    cmd(archiver, "delete", "-a", "archive1")
    # threshold 0: every pack with any unused bytes is rewritten
    cmd(archiver, "compact", "-v", "--threshold", "0", exit_code=0)

    # the persisted chunk index may only reference packs that still exist
    repository = open_repository(archiver)
    with repository:
        pack_names = {info.name for info in repository.store_list("packs")}
        for id, entry in repository.chunks.iteritems():
            assert bin_to_hex(entry.pack_id) in pack_names, f"chunk {bin_to_hex(id)} points at a deleted pack"

    # the kept chunk moved into a new pack; extracting must read it from there
    with changedir("output"):
        cmd(archiver, "extract", "archive2")
        with open(os.path.join("input", "file_kept"), "rb") as fd:
            assert fd.read() == contents_kept

    # 9850: delete the remaining archive and compact again - must not crash with ObjectNotFound
    cmd(archiver, "delete", "-a", "archive2")
    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Finished compaction" in output


def test_compact_dry_run_reports_and_changes_nothing(archivers, request):
    # --dry-run prints the would-free estimate (issue #9379) and must not touch the repository.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    cmd(archiver, "delete", "-a", "archive")

    out = cmd(archiver, "compact", "--dry-run", "-v", exit_code=0)
    assert "Would free" in out  # the estimate is reported

    # proof nothing was removed: a real compact afterwards still finds the unused objects to delete
    out2 = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Deleting 0 unused objects" not in out2


def test_compact_files_cache_cleanup(archivers, request):
    """Test that files cache files for deleted archives are removed during compact."""
    archiver = request.getfixturevalue(archivers)

    # Create repository and archives
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive1")
    create_src_archive(archiver, "archive2")
    create_src_archive(archiver, "archive3")

    # Get repository ID
    output = cmd(archiver, "repo-info")
    for line in output.splitlines():
        if "Repository ID:" in line:
            repo_id = line.split(":", 1)[1].strip()
            break
    else:
        pytest.fail("Could not find repository ID in info output")

    # Check cache directory for files cache files
    cache_dir = Path(get_cache_dir(repo_id, create=False))
    if not cache_dir.exists():
        pytest.skip("Cache directory does not exist, skipping test")

    # Get initial files cache files
    try:
        initial_cache_files = set(discover_files_cache_names(cache_dir))
    except (FileNotFoundError, PermissionError):
        pytest.skip("Could not access cache directory, skipping test")

    # Get expected cache files for remaining archives
    expected_cache_files = {files_cache_name(name) for name in ["archive1", "archive2", "archive3"]}
    assert expected_cache_files == initial_cache_files, "Unexpected cache files found"

    # Delete one archive
    cmd(archiver, "delete", "-a", "archive2")

    # Run compact
    output = cmd(archiver, "compact", "-v")
    assert "Cleaning up files cache" in output

    # Check that files cache for deleted archive is removed
    try:
        remaining_cache_files = set(discover_files_cache_names(cache_dir))
    except (FileNotFoundError, PermissionError):
        pytest.fail("Could not access cache directory after compact")

    # Get expected cache files for remaining archives
    expected_cache_files = {files_cache_name(name) for name in ["archive1", "archive3"]}
    assert expected_cache_files == remaining_cache_files, "Unexpected cache files found"
