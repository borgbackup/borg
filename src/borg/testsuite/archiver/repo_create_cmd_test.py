import os
from unittest.mock import patch

import pytest

from ...helpers.errors import Error, CancelledByUser
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from . import cmd, generate_archiver_tests, RK_ENCRYPTION, KF_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_repo_create_interrupt(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("patches object")

    def raise_eof(*args, **kwargs):
        raise EOFError

    with patch.object(FlexiKey, "create", raise_eof):
        if archiver.FORK_DEFAULT:
            cmd(archiver, "repo-create", RK_ENCRYPTION, exit_code=2)
        else:
            with pytest.raises(CancelledByUser):
                cmd(archiver, "repo-create", RK_ENCRYPTION)

    assert not os.path.exists(archiver.repository_location)


def test_repo_create_requires_encryption_option(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", exit_code=2)


def test_repo_create_refuse_to_overwrite_keyfile(archivers, request, monkeypatch):
    #  BORG_KEY_FILE=something borg repo-create should quit if "something" already exists.
    #  See: https://github.com/borgbackup/borg/pull/6046
    archiver = request.getfixturevalue(archivers)
    keyfile = os.path.join(archiver.tmpdir, "keyfile")
    monkeypatch.setenv("BORG_KEY_FILE", keyfile)
    original_location = archiver.repository_location
    archiver.repository_location = original_location + "0"
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    with open(keyfile) as file:
        before = file.read()
    archiver.repository_location = original_location + "1"
    arg = ("repo-create", KF_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)
    with open(keyfile) as file:
        after = file.read()
    assert before == after
