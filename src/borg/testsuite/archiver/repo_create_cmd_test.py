import os
from unittest.mock import patch

import pytest

from ...helpers.errors import Error, CancelledByUser
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from . import cmd, generate_archiver_tests, RK_ENCRYPTION, KF_ENCRYPTION, KF_LOCATION

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


@pytest.mark.parametrize(
    "extra_args, expected",
    [
        # --encryption x --id-hash -> crypto suite shown by "borg repo-info"
        (["--encryption=aes256-ocb"], "Yes (repokey, aes256-ocb, sha256)"),  # default id-hash is sha256
        (["--encryption=aes256-ocb", "--id-hash=sha256"], "Yes (repokey, aes256-ocb, sha256)"),
        (["--encryption=aes256-ocb", "--id-hash=blake3"], "Yes (repokey, aes256-ocb, blake3)"),
        (["--encryption=chacha20-poly1305"], "Yes (repokey, chacha20-poly1305, sha256)"),
        (["--encryption=chacha20-poly1305", "--id-hash=blake3"], "Yes (repokey, chacha20-poly1305, blake3)"),
        (["--encryption=authenticated"], "No (repokey, authenticated, sha256)"),
        (["--encryption=authenticated", "--id-hash=blake3"], "No (repokey, authenticated, blake3)"),
        (["--encryption=none"], "No"),
    ],
)
def test_repo_create_encryption_id_hash_combinations(archivers, request, extra_args, expected):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", *extra_args)
    info = cmd(archiver, "repo-info")
    assert expected in info


def test_repo_create_none_rejects_blake3(archivers, request):
    # "none" (plaintext) has no key, so it only supports the sha256 id-hash.
    archiver = request.getfixturevalue(archivers)
    arg = ("repo-create", "--encryption=none", "--id-hash=blake3")
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)


def test_repo_create_rejects_legacy_combined_mode(archivers, request):
    # clean break: the old combined "--encryption" names are no longer accepted (argparse choices).
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=blake3-aes-ocb", exit_code=2)


def test_repo_create_refuse_to_overwrite_keyfile(archivers, request, monkeypatch):
    #  BORG_KEY_FILE=something borg repo-create should quit if "something" already exists.
    #  See: https://github.com/borgbackup/borg/pull/6046
    archiver = request.getfixturevalue(archivers)
    keyfile = os.path.join(archiver.tmpdir, "keyfile")
    monkeypatch.setenv("BORG_KEY_FILE", keyfile)
    original_location = archiver.repository_location
    archiver.repository_location = original_location + "0"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    with open(keyfile) as file:
        before = file.read()
    archiver.repository_location = original_location + "1"
    arg = ("repo-create", KF_ENCRYPTION, KF_LOCATION)
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)
    with open(keyfile) as file:
        after = file.read()
    assert before == after
