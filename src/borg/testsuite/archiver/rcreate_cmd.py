import os
from unittest.mock import patch

import pytest

from ...helpers.errors import Error
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from ...repository import Repository
from .. import environment_variable
from . import cmd, RK_ENCRYPTION, KF_ENCRYPTION


def pytest_generate_tests(metafunc):
    # Generate tests for different scenarios: local repository, remote repository, and using the borg binary.
    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", ["archiver", "remote_archiver", "binary_archiver"])


def test_rcreate_parent_dirs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("does not raise Exception, but sets rc==2")

    parent_path = os.path.join(archiver.tmpdir, "parent1", "parent2")
    repository_path = os.path.join(parent_path, "repository")
    repository_location = archiver.prefix + repository_path
    with pytest.raises(Repository.ParentPathDoesNotExist):
        # normal borg rcreate does NOT create missing parent dirs
        cmd(archiver, f"--repo={repository_location}", "rcreate", "--encryption=none")
    # but if told so, it does:
    cmd(archiver, f"--repo={repository_location}", "rcreate", "--encryption=none", "--make-parent-dirs")
    assert os.path.exists(parent_path)


def test_rcreate_interrupt(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location
    if archiver.EXE:
        pytest.skip("patches object")

    def raise_eof(*args, **kwargs):
        raise EOFError

    with patch.object(FlexiKey, "create", raise_eof):
        cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION, exit_code=1)
    assert not os.path.exists(repo_location)


def test_rcreate_requires_encryption_option(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", exit_code=2)


def test_rcreate_nested_repositories(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        cmd(archiver, f"--repo={repo_location}/nested", "rcreate", RK_ENCRYPTION, exit_code=2)
    else:
        with pytest.raises(Repository.AlreadyExists):
            cmd(archiver, f"--repo={repo_location}/nested", "rcreate", RK_ENCRYPTION)


def test_rcreate_refuse_to_overwrite_keyfile(archivers, request):
    #  BORG_KEY_FILE=something borg rcreate should quit if "something" already exists.
    #  See: https://github.com/borgbackup/borg/pull/6046
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location

    keyfile = os.path.join(archiver.tmpdir, "keyfile")
    with environment_variable(BORG_KEY_FILE=keyfile):
        cmd(archiver, f"--repo={repo_location}0", "rcreate", KF_ENCRYPTION)
        with open(keyfile) as file:
            before = file.read()
        arg = (f"--repo={repo_location}1", "rcreate", KF_ENCRYPTION)
        if archiver.FORK_DEFAULT:
            cmd(archiver, *arg, exit_code=2)
        else:
            with pytest.raises(Error):
                cmd(archiver, *arg)
        with open(keyfile) as file:
            after = file.read()
        assert before == after
