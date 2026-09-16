import os

import pytest

from ...constants import *  # NOQA
from ...helpers import CancelledByUser, Error
from . import create_regular_file, cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_delete_repo(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "test.2", "input")
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "no"
    if archiver.FORK_DEFAULT:
        expected_ec = CancelledByUser().exit_code
        cmd(archiver, "repo-delete", exit_code=expected_ec)
    else:
        with pytest.raises(CancelledByUser):
            cmd(archiver, "repo-delete")
    assert os.path.exists(archiver.repository_path)
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    cmd(archiver, "repo-delete")
    # Make sure the repository is gone
    assert not os.path.exists(archiver.repository_path)


def test_delete_repo_force(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    # with --force, no confirmation is asked for, not even the env var is considered.
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "no"
    cmd(archiver, "repo-delete", "--force")
    # Make sure the repository is gone
    assert not os.path.exists(archiver.repository_path)


def test_delete_store_without_config(archivers, request):
    # a store without repository config (e.g. the leftover of an interrupted repo-create, or a repository
    # that lost its config) can only be deleted with --force.
    from ...repository import Repository

    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("creates the store via the Python API")
    with Repository(archiver.repository_path, exclusive=True, create=True, create_config=False):
        pass
    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "repo-delete", exit_code=2)
        assert "requires the --force option" in output
    else:
        with pytest.raises(Error, match="requires the --force option"):
            cmd(archiver, "repo-delete")
    cmd(archiver, "repo-delete", "--force", "--dry-run")
    assert os.path.exists(archiver.repository_path)
    cmd(archiver, "repo-delete", "--force")
    assert not os.path.exists(archiver.repository_path)
    # a directory with data in it does not look like a borg store: refused even with --force.
    os.mkdir(archiver.repository_path)
    create_regular_file(archiver.repository_path, "file", contents=b"some data")
    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "repo-delete", "--force", exit_code=2)
        assert "does not look like a borg store" in output
    else:
        with pytest.raises(Error, match="does not look like a borg store"):
            cmd(archiver, "repo-delete", "--force")
    assert os.listdir(archiver.repository_path) == ["file"]
    os.unlink(os.path.join(archiver.repository_path, "file"))
    os.rmdir(archiver.repository_path)
    # a repository with an archive that lost its config: --force destroys it.
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "test", "input")
    os.unlink(os.path.join(archiver.repository_path, "config", "config"))
    cmd(archiver, "repo-delete", "--force")
    assert not os.path.exists(archiver.repository_path)
