import pytest

from ...constants import *  # NOQA
from ...helpers import CommandError
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_delete_options(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "test.2", "input")
    cmd(archiver, "create", "test.3", "input")
    cmd(archiver, "create", "another_test.1", "input")
    cmd(archiver, "create", "another_test.2", "input")
    cmd(archiver, "delete", "--match-archives", "sh:another_*")
    cmd(archiver, "delete", "--last", "1")  # test.3
    cmd(archiver, "delete", "-a", "test")
    cmd(archiver, "extract", "test.2", "--dry-run")  # still there?
    cmd(archiver, "delete", "-a", "test.2")
    output = cmd(archiver, "repo-list")
    assert output == ""  # no archives left!


def test_delete_date_filters_are_a_selection(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    # a date-based filter is an explicit archive selection, so the delete-all guard must not trigger
    output = cmd(archiver, "delete", "--dry-run", "--list", "--newest", "1d")
    assert "Would delete" in output


def test_delete_multiple(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "delete", "-a", "test1")
    cmd(archiver, "delete", "-a", "test2")
    assert not cmd(archiver, "repo-list")


def test_delete_all_without_filter_aborts(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "create", "test3", "input")
    # Without NAME, -a / --match-archives, --first or --last, borg must refuse to delete everything.
    # The guard triggers before any archive is considered, so it also applies to --dry-run.
    msg = "if you really want to delete all archives"
    for extra_args in ([], ["--dry-run", "--list"]):
        if archiver.FORK_DEFAULT:
            output = cmd(archiver, "delete", *extra_args, exit_code=CommandError().exit_code)
            assert msg in output
            assert "Would delete" not in output
        else:
            with pytest.raises(CommandError, match=msg):
                cmd(archiver, "delete", *extra_args)
    output = cmd(archiver, "repo-list")  # no archive was deleted
    assert "test1" in output
    assert "test2" in output
    assert "test3" in output


def test_delete_all_with_match_archives(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "delete", "-a", "sh:*")  # explicitly asking for all archives is fine
    assert cmd(archiver, "repo-list") == ""


def test_delete_first_last(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "create", "test3", "input")
    cmd(archiver, "delete", "--first", "1", "--sort-by", "name")  # test1
    output = cmd(archiver, "repo-list")
    assert "test1" not in output
    assert "test2" in output
    assert "test3" in output
    cmd(archiver, "delete", "--last", "1", "--sort-by", "name")  # test3
    output = cmd(archiver, "repo-list")
    assert "test2" in output
    assert "test3" not in output


def test_delete_ignore_protected(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "tag", "--add=@PROT", "test1")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "delete", "-a", "test1")
    cmd(archiver, "delete", "-a", "test2")
    cmd(archiver, "delete", "-a", "sh:test*")
    output = cmd(archiver, "repo-list")
    assert "@PROT" in output
    assert "test1" in output
    assert "test2" not in output


def test_delete_name_and_match_archives_are_combined(archivers, request, monkeypatch):
    """In a shared repository, different hosts may use the same archive name - NAME alone is ambiguous then."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for host in ("host1", "host2"):
        monkeypatch.setenv("BORG_HOSTNAME", host)
        cmd(archiver, "create", "home", "input")
    monkeypatch.delenv("BORG_HOSTNAME")
    msg = "needed to match precisely one archive"
    if archiver.FORK_DEFAULT:
        cmd(archiver, "delete", "home", exit_code=CommandError().exit_code)
    else:
        with pytest.raises(CommandError, match=msg):
            cmd(archiver, "delete", "home")
    # NAME is ANDed with -a / --match-archives, so this selects one specific host's archive:
    cmd(archiver, "delete", "home", "-a", "host:host1")
    output = cmd(archiver, "repo-list", "--format={hostname}{NL}")
    assert output.strip() == "host2"
