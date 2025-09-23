from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...helpers import get_cache_dir
from ...cache import files_cache_name, discover_files_cache_names
from . import cmd, create_src_archive, generate_archiver_tests, RK_ENCRYPTION

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
