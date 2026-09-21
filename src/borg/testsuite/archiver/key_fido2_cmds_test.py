"""CLI tests for FIDO2-protected borg keys (borg key add --fido2-device etc.).

Local (in-process) only: the fake token is monkeypatched into borg.crypto.fido2, which a
forked borg binary would not see. The fake_token fixture comes from the key-layer tests.
"""

import os

import pytest

from ...constants import KEY_ALGORITHMS  # NOQA
from ...crypto.key import Fido2Error
from ...helpers import CommandError
from ..crypto.key_fido2_test import fake_token  # noqa: F401 - pytest fixture import
from . import RK_ENCRYPTION, cmd, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA

DEFAULT_PASSPHRASE = "waytooeasyonlyfortests"  # see set_env_variables fixture in conftest


@pytest.fixture
def fido2_repo(archivers, request, fake_token):  # noqa: F811
    """A repokey repository with the admin (passphrase) key plus one fido2 key ("token")."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # admin = DEFAULT_PASSPHRASE
    cmd(archiver, "key", "add", "--fido2-device", "--label", "token")
    return archiver


def test_key_add_fido2_and_unlock(fido2_repo, fake_token):  # noqa: F811
    archiver = fido2_repo
    out = cmd(archiver, "key", "list")
    assert "token" in out
    assert "fido2 hmac-secret" in out
    # the passphrase unlocks via the admin key, without driving the token.
    cmd(archiver, "repo-list")
    assert fake_token.derive_calls == []
    # without a passphrase, the fido2 borg key unlocks - with exactly one token interaction.
    del os.environ["BORG_PASSPHRASE"]
    cmd(archiver, "repo-list")
    assert len(fake_token.derive_calls) == 1


def test_key_add_fido2_touchless(archivers, request, fake_token):  # noqa: F811
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "key", "add", "--fido2-device", "--fido2-touch=no", "--label", "token")
    del os.environ["BORG_PASSPHRASE"]
    cmd(archiver, "repo-list")
    assert fake_token.derive_calls[-1]["up_required"] is False


def test_key_add_fido2_touch_no_needs_device(archivers, request, fake_token):  # noqa: F811
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with pytest.raises(CommandError, match="--fido2-touch=no"):
        cmd(archiver, "key", "add", "--fido2-touch=no", "--label", "token")


def test_key_add_fido2_no_device_plugged_in(archivers, request, fake_token):  # noqa: F811
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    fake_token.present = False
    with pytest.raises(Fido2Error):
        cmd(archiver, "key", "add", "--fido2-device", "--label", "token")
    # the failed enrollment left the key set unchanged.
    out = cmd(archiver, "key", "list")
    assert "token" not in out


def test_key_export_fido2_warns(fido2_repo, tmp_path):
    output = cmd(fido2_repo, "key", "export", str(tmp_path / "exported"), "--label", "token")
    assert "useless without" in output


def test_key_remove_fido2(fido2_repo, fake_token):  # noqa: F811
    archiver = fido2_repo
    cmd(archiver, "key", "remove", "--label", "token")
    out = cmd(archiver, "key", "list")
    assert "token" not in out and "admin" in out
    # without a passphrase and without the fido2 borg key, unlocking fails.
    del os.environ["BORG_PASSPHRASE"]
    with pytest.raises(Exception):  # noqa: B017 - PasswordRetriesExceeded via prompts, or EOF
        cmd(archiver, "repo-list")


def test_key_change_location_fido2_copies_verbatim(fido2_repo, fake_token):  # noqa: F811
    archiver = fido2_repo
    enrolls_before = fake_token.enroll_calls
    # unlock via the fido2 borg key, then move it (the unlocked key) to keyfile storage.
    del os.environ["BORG_PASSPHRASE"]
    cmd(archiver, "key", "change-location", "keyfile")
    out = cmd(archiver, "key", "list")
    rows = [line for line in out.splitlines() if "token" in line]
    assert len(rows) == 1 and "keyfile" in rows[0]
    # verbatim move: no re-enrollment happened (that would invalidate exported backups).
    assert fake_token.enroll_calls == enrolls_before
    # it still unlocks from the keyfile, and moves back into the repository.
    cmd(archiver, "key", "change-location", "repokey")
    out = cmd(archiver, "key", "list")
    rows = [line for line in out.splitlines() if "token" in line]
    assert len(rows) == 1 and "repokey" in rows[0]
    assert fake_token.enroll_calls == enrolls_before
    cmd(archiver, "repo-list")
