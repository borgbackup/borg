import os
from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...archiver.compact_cmd import ArchiveGarbageCollector
from ...hashindex import ChunkIndex
from ...helpers import get_cache_dir, bin_to_hex
from ...cache import files_cache_name, discover_files_cache_names, list_chunkindex_hashes
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, create_regular_file, create_src_archive, generate_archiver_tests, open_repository, RK_ENCRYPTION
from . import changedir
from ..hashindex_test import H
from ..repository_test import fchunk, pdchunk

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
        assert "Repository has data stored in 0 objects." in output
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
        assert "Repository has data stored in 0 objects." in output
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
        assert "Repository has data stored in 0 objects." not in output
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
    updated chunk index, the still-existing cache/chunks.* must not claim that the deleted
    objects are still present. Otherwise a later "borg create" trusts the stale index, does
    not re-upload the affected chunks and silently produces an archive with dangling object
    references (which extracts to zero bytes).

    The fix invalidates all cached chunk indexes before the first delete, so an interruption
    is conservative: the next client rebuilds the index from actual repository contents and
    re-uploads any deleted data. This is tested for both compact paths (default and --stats).
    """
    from ...archiver.compact_cmd import ArchiveGarbageCollector

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
        gc = ArchiveGarbageCollector(repository, manifest, stats=stats, iec=False)

        def interrupt():
            raise KeyboardInterrupt("simulated interruption before save_chunk_index")

        monkeypatch.setattr(gc, "save_chunk_index", interrupt)
        with pytest.raises(KeyboardInterrupt):
            gc.garbage_collect()

    # The objects were deleted, so no readable cached chunk index may still list them.
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
    cache_dir = Path(get_cache_dir()) / repo_id
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


def _pack_names(repo):
    # set of pack file names (hex pack_ids) currently present in the store.
    return {info.name for info in repo.store.list("packs")}


def _load_obj(repo, index, chunk_id):
    # read an object's stored bytes via its current index location (same range-load get() does).
    entry = index[chunk_id]
    return repo.store.load("packs/" + bin_to_hex(entry.pack_id), offset=entry.obj_offset, size=entry.obj_size)


def test_compact_drops_whole_unused_packs(tmp_path):
    """N=1: each pack holds exactly one object, so compact reclaims space by dropping whole
    unused pack files -- there is no per-object delete. The used object's pack stays; the
    unused ones are removed as a whole."""
    repo_location = os.fspath(tmp_path / "repo")
    with Repository(repo_location, exclusive=True, create=True) as repo:
        # default max_count == 1: one object per pack.
        for i in range(3):
            repo.put(H(i), fchunk(b"data%d" % i))
        repo.flush()
        index = repo.chunks
        assert len(_pack_names(repo)) == 3

        # simulate analyze_archives(): start from "unused" (put() marks new chunks F_USED), then
        # mark only H(0) as referenced; H(1) and H(2) stay unused.
        gc = ArchiveGarbageCollector(repo, manifest=None, stats=False, iec=False)
        gc.chunks = index
        for i in range(3):
            entry = index[H(i)]
            flags = ChunkIndex.F_USED if i == 0 else ChunkIndex.F_NONE
            index[H(i)] = entry._replace(flags=flags)

        gc.compact_packs()

        # only the used object's pack survives; the two unused single-object packs are gone.
        assert _pack_names(repo) == {bin_to_hex(index[H(0)].pack_id)}
        assert H(0) in index
        assert H(1) not in index and H(2) not in index
        assert pdchunk(_load_obj(repo, index, H(0))) == b"data0"


def test_compact_copy_forward_mixed_pack(tmp_path):
    """N>1: a single pack can hold both used and unused objects. compact must keep the used
    ones by copying them into a fresh pack and drop the old pack as a whole -- never delete a
    single object in place. We force max_count > 1 to build such a mixed pack, since the N=1
    production path never produces one. This proves the copy-forward design ahead of N>1."""
    repo_location = os.fspath(tmp_path / "repo")
    with Repository(repo_location, exclusive=True, create=True) as repo:
        # build ONE pack holding three objects by bundling (max_count = 3).
        repo._pack_writer.max_count = 3
        repo.put(H(0), fchunk(b"data0"))
        repo.put(H(1), fchunk(b"data1"))
        repo.put(H(2), fchunk(b"data2"))  # third add fills the pack and flushes it
        repo.flush()

        index = repo.chunks
        old_pack_id = index[H(0)].pack_id
        assert {index[H(i)].pack_id for i in range(3)} == {old_pack_id}  # all three share one pack
        assert _pack_names(repo) == {bin_to_hex(old_pack_id)}

        # simulate analyze_archives(): start from "unused" (put() marks new chunks F_USED), then
        # mark H(0) and H(2) as referenced; H(1) stays unused.
        gc = ArchiveGarbageCollector(repo, manifest=None, stats=False, iec=False)
        gc.chunks = index
        for i in range(3):
            entry = index[H(i)]
            flags = ChunkIndex.F_USED if i in (0, 2) else ChunkIndex.F_NONE
            index[H(i)] = entry._replace(flags=flags)

        gc.compact_packs()

        # the unused object is gone from the index; the survivors moved into a new pack.
        assert H(1) not in index
        new_pack_id = index[H(0)].pack_id
        assert new_pack_id != old_pack_id
        assert index[H(2)].pack_id == new_pack_id

        # old pack dropped whole, new pack present, survivors still hold their original bytes.
        assert _pack_names(repo) == {bin_to_hex(new_pack_id)}
        assert pdchunk(_load_obj(repo, index, H(0))) == b"data0"
        assert pdchunk(_load_obj(repo, index, H(2))) == b"data2"
