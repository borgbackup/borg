import os
from unittest.mock import patch

import pytest

from ...helpers.errors import Error, CancelledByUser
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from ...repository import Repository
from . import cmd, generate_archiver_tests, RK_ENCRYPTION, KF_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_rcreate_parent_dirs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("does not raise Exception, but sets rc==2")
    remote_repo = archiver.get_kind() == "remote"
    parent_path = os.path.join(archiver.tmpdir, "parent1", "parent2")
    repository_path = os.path.join(parent_path, "repository")
    archiver.repository_location = ("ssh://__testsuite__" + repository_path) if remote_repo else repository_path
    with pytest.raises(Repository.ParentPathDoesNotExist):
        # normal borg rcreate does NOT create missing parent dirs
        cmd(archiver, "rcreate", "--encryption=none")
    # but if told so, it does:
    cmd(archiver, "rcreate", "--encryption=none", "--make-parent-dirs")
    assert os.path.exists(parent_path)


def test_rcreate_interrupt(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("patches object")

    def raise_eof(*args, **kwargs):
        raise EOFError

    with patch.object(FlexiKey, "create", raise_eof):
        if archiver.FORK_DEFAULT:
            cmd(archiver, "rcreate", RK_ENCRYPTION, exit_code=2)
        else:
            with pytest.raises(CancelledByUser):
                cmd(archiver, "rcreate", RK_ENCRYPTION)

    assert not os.path.exists(archiver.repository_location)


def test_rcreate_requires_encryption_option(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", exit_code=2)


def test_rcreate_nested_repositories(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    archiver.repository_location += "/nested"
    if archiver.FORK_DEFAULT:
        cmd(archiver, "rcreate", RK_ENCRYPTION, exit_code=2)
    else:
        with pytest.raises(Repository.AlreadyExists):
            cmd(archiver, "rcreate", RK_ENCRYPTION)


def test_rcreate_refuse_to_overwrite_keyfile(archivers, request, monkeypatch):
    #  BORG_KEY_FILE=something borg rcreate should quit if "something" already exists.
    #  See: https://github.com/borgbackup/borg/pull/6046
    archiver = request.getfixturevalue(archivers)
    keyfile = os.path.join(archiver.tmpdir, "keyfile")
    monkeypatch.setenv("BORG_KEY_FILE", keyfile)
    original_location = archiver.repository_location
    archiver.repository_location = original_location + "0"
    cmd(archiver, "rcreate", KF_ENCRYPTION)
    with open(keyfile) as file:
        before = file.read()
    archiver.repository_location = original_location + "1"
    arg = ("rcreate", KF_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)
    with open(keyfile) as file:
        after = file.read()
    assert before == after
