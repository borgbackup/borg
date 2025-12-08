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


def test_repo_create_keyfile_same_path_creates_new_keys(archivers, request):
    """Regression test for GH issue #6230.

    When creating a new keyfile-encrypted repository at the same filesystem path
    multiple times (e.g., after moving/unmounting the previous one), Borg must not
    overwrite or reuse the existing key file. Instead, it should create a new key
    file in the keys directory, appending a numeric suffix like .2, .3, ...
    """
    archiver = request.getfixturevalue(archivers)

    # First creation at path A
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    keys = sorted(os.listdir(archiver.keys_path))
    assert len(keys) == 1
    base_key = keys[0]
    base_path = os.path.join(archiver.keys_path, base_key)
    with open(base_path, "rb") as f:
        base_contents = f.read()

    # Simulate moving/unmounting the repo by removing the path to allow re-create at the same path
    import shutil

    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    keys = sorted(os.listdir(archiver.keys_path))
    assert len(keys) == 2
    assert base_key in keys
    # The new file should be base_key suffixed with .2
    assert any(k == base_key + ".2" for k in keys)
    second_path = os.path.join(archiver.keys_path, base_key + ".2")
    with open(second_path, "rb") as f:
        second_contents = f.read()
    assert second_contents != base_contents

    # Remove repo again and create a third time at same path
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    keys = sorted(os.listdir(archiver.keys_path))
    assert len(keys) == 3
    assert any(k == base_key + ".3" for k in keys)
    third_path = os.path.join(archiver.keys_path, base_key + ".3")
    with open(third_path, "rb") as f:
        third_contents = f.read()
    # Ensure all keys are distinct
    assert third_contents != base_contents
    assert third_contents != second_contents
