import os
from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...helpers import get_cache_dir, bin_to_hex
from ...hashindex import ChunkIndex
from ...repository import Repository
from ...cache import files_cache_name, discover_files_cache_names, list_chunkindex_hashes
from ...manifest import Manifest
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
    updated chunk index, the still-existing index/* must not claim that the deleted
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
        gc = ArchiveGarbageCollector(repository, manifest, stats=stats, iec=False, threshold=40.0)

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


def test_compact_packs_respects_threshold(tmp_path):
    # Two multi-object packs in one repo, then pack-level compaction at a 40% threshold. The pack that
    # wastes 2/3 of its bytes is rewritten down to its single survivor (and its old file deleted); the
    # pack that wastes only 1/3 stays untouched, since copying its survivors to reclaim that little is
    # not worth it. This covers the rewrite, leave-alone and keep/drop split unique to multi-object packs.
    from ...archiver.compact_cmd import ArchiveGarbageCollector

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

        # wasteful pack was rewritten: the survivor reads back, the dropped objects and the old file are gone
        assert pdchunk(repository.get(H(0))) == b"DATA0"
        assert repository.get(H(1), raise_missing=False) is None
        assert repository.get(H(2), raise_missing=False) is None
        # frugal pack stayed below threshold: untouched, every object (even the unused H5) still present
        for i in range(3, 6):
            assert pdchunk(repository.get(H(i))) == f"DATA{i}".encode()
        pack_names = [info.name for info in repository.store_list("packs")]
        assert bin_to_hex(wasteful_pack) not in pack_names
        assert bin_to_hex(frugal_pack) in pack_names


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
