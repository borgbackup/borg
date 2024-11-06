from ...constants import *  # NOQA
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_undelete_single(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "normal", "input")
    cmd(archiver, "create", "deleted", "input")
    cmd(archiver, "delete", "deleted")
    output = cmd(archiver, "repo-list")
    assert "normal" in output
    assert "deleted" not in output
    cmd(archiver, "undelete", "deleted")
    output = cmd(archiver, "repo-list")
    assert "normal" in output
    assert "deleted" in output  # it's back!
    cmd(archiver, "check")


def test_undelete_multiple_dryrun(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "normal", "input")
    cmd(archiver, "create", "deleted1", "input")
    cmd(archiver, "create", "deleted2", "input")
    cmd(archiver, "delete", "deleted1")
    cmd(archiver, "delete", "deleted2")
    output = cmd(archiver, "repo-list")
    assert "normal" in output
    assert "deleted1" not in output
    assert "deleted2" not in output
    output = cmd(archiver, "undelete", "--dry-run", "--list", "-a", "sh:*")
    assert "normal" not in output  # not a candidate for undeletion
    assert "deleted1" in output  # candidate for undeletion
    assert "deleted2" in output  # candidate for undeletion
    output = cmd(archiver, "repo-list")  # nothing change, it was a dry-run
    assert "normal" in output
    assert "deleted1" not in output
    assert "deleted2" not in output


def test_undelete_multiple_run(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "normal", "input")
    cmd(archiver, "create", "deleted1", "input")
    cmd(archiver, "create", "deleted2", "input")
    cmd(archiver, "delete", "deleted1")
    cmd(archiver, "delete", "deleted2")
    output = cmd(archiver, "repo-list")
    assert "normal" in output
    assert "deleted1" not in output
    assert "deleted2" not in output
    output = cmd(archiver, "undelete", "--list", "-a", "sh:*")
    assert "normal" not in output  # not undeleted
    assert "deleted1" in output  # undeleted
    assert "deleted2" in output  # undeleted
    output = cmd(archiver, "repo-list")  # nothing change, it was a dry-run
    assert "normal" in output
    assert "deleted1" in output
    assert "deleted2" in output
