from ...constants import *  # NOQA
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


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


def test_delete_multiple(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "delete", "-a", "test1")
    cmd(archiver, "delete", "-a", "test2")
    assert not cmd(archiver, "repo-list")


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
