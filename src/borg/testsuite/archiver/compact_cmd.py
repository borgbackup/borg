from ...constants import *  # NOQA
from . import cmd, create_src_archive, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_compact_empty_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "rcreate", RK_ENCRYPTION)

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Starting compaction" in output
    assert "Repository size is 0 B in 0 objects." in output
    assert "Finished compaction" in output


def test_compact_after_deleting_all_archives(archivers, request):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "archive")
    cmd(archiver, "delete", "-a", "archive", exit_code=0)

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Starting compaction" in output
    assert "Deleting " in output
    assert "Repository size is 0 B in 0 objects." in output
    assert "Finished compaction" in output


def test_compact_after_deleting_some_archives(archivers, request):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "archive1")
    create_src_archive(archiver, "archive2")
    cmd(archiver, "delete", "-a", "archive1", exit_code=0)

    output = cmd(archiver, "compact", "-v", exit_code=0)
    assert "Starting compaction" in output
    assert "Deleting " in output
    assert "Repository size is 0 B in 0 objects." not in output
    assert "Finished compaction" in output
