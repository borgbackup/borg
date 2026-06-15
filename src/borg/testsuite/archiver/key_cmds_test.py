import binascii
import os
from hashlib import sha256

import pytest

from ...constants import *  # NOQA
from ...constants import KeyBlobStorage
from ...crypto.key import AESOCBKey, CHPOKey, Passphrase, is_keyfile, keyfile_parse
from ...crypto.keymanager import RepoIdMismatch, NotABorgKeyFile
from ...helpers import CommandError
from ...helpers import bin_to_hex, hex_to_bin
from ...helpers import msgpack
from ...repository import Repository
from ..crypto.key_test import TestKey
from . import (
    RK_ENCRYPTION,
    KF_ENCRYPTION,
    KF_LOCATION,
    cmd,
    _extract_repository_id,
    _set_repository_id,
    generate_archiver_tests,
)

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_change_passphrase(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
    # Here we have both BORG_PASSPHRASE and BORG_NEW_PASSPHRASE set:
    cmd(archiver, "key", "change-passphrase")
    os.environ["BORG_PASSPHRASE"] = "newpassphrase"
    cmd(archiver, "repo-list")


def test_change_location_to_keyfile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    log = cmd(archiver, "repo-info")
    assert "(repokey" in log
    cmd(archiver, "key", "change-location", "keyfile")
    log = cmd(archiver, "repo-info")
    assert "(keyfile" in log


def test_change_location_to_b3keyfile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=aes256-ocb", "--id-hash=blake3")
    log = cmd(archiver, "repo-info")
    assert "(repokey, BLAKE3" in log
    cmd(archiver, "key", "change-location", "keyfile")
    log = cmd(archiver, "repo-info")
    assert "(keyfile, BLAKE3" in log


def test_change_location_to_repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    log = cmd(archiver, "repo-info")
    assert "(keyfile" in log
    cmd(archiver, "key", "change-location", "repokey")
    log = cmd(archiver, "repo-info")
    assert "(repokey" in log


def test_change_location_to_b3repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=aes256-ocb", "--id-hash=blake3", KF_LOCATION)
    log = cmd(archiver, "repo-info")
    assert "(keyfile, BLAKE3" in log
    cmd(archiver, "key", "change-location", "repokey")
    log = cmd(archiver, "repo-info")
    assert "(repokey, BLAKE3" in log


def test_change_location_authenticated_to_keyfile(archivers, request):
    # authenticated mode does not encrypt, but it still has a key whose location is configurable.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=authenticated")
    log = cmd(archiver, "repo-info")
    assert "(repokey, authenticated SHA256)" in log
    cmd(archiver, "key", "change-location", "keyfile")
    [key_filename] = os.listdir(archiver.keys_path)
    assert key_filename  # key blob now lives as a keyfile
    log = cmd(archiver, "repo-info")
    assert "(keyfile, authenticated SHA256)" in log


def test_change_location_authenticated_to_repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=authenticated", KF_LOCATION)
    assert os.listdir(archiver.keys_path)  # key blob created as a keyfile
    log = cmd(archiver, "repo-info")
    assert "(keyfile, authenticated SHA256)" in log
    cmd(archiver, "key", "change-location", "repokey")
    assert os.listdir(archiver.keys_path) == []  # keyfile removed after moving into the repo
    log = cmd(archiver, "repo-info")
    assert "(repokey, authenticated SHA256)" in log


def test_keyfile_name_is_content_sha256(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    [key_filename] = os.listdir(archiver.keys_path)
    key_path = os.path.join(archiver.keys_path, key_filename)
    with open(key_path, "rb") as fd:
        key_content = fd.read()
    assert key_filename == sha256(key_content).hexdigest()


def test_change_passphrase_renames_keyfile_to_new_sha256(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    [old_key_filename] = os.listdir(archiver.keys_path)
    old_key_path = os.path.join(archiver.keys_path, old_key_filename)
    os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
    cmd(archiver, "key", "change-passphrase")
    os.environ["BORG_PASSPHRASE"] = "newpassphrase"
    [new_key_filename] = os.listdir(archiver.keys_path)
    new_key_path = os.path.join(archiver.keys_path, new_key_filename)
    assert old_key_filename != new_key_filename
    assert not os.path.exists(old_key_path)
    with open(new_key_path, "rb") as fd:
        key_content = fd.read()
    assert new_key_filename == sha256(key_content).hexdigest()
    cmd(archiver, "repo-list")


def test_borg_key_file_env_keeps_explicit_path(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    explicit_key_path = os.path.join(archiver.output_path, "explicit-key")
    monkeypatch.setenv("BORG_KEY_FILE", explicit_key_path)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    assert os.path.isfile(explicit_key_path)
    assert os.listdir(archiver.keys_path) == []


def test_key_export_keyfile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_file = archiver.output_path + "/exported"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    repo_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "key", "export", export_file)

    with open(export_file) as fd:
        export_contents = fd.read()

    assert is_keyfile(export_contents, bin_to_hex(repo_id))

    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]

    with open(key_file) as fd:
        key_contents = fd.read()

    assert key_contents == export_contents

    os.unlink(key_file)

    cmd(archiver, "key", "import", export_file, "--key-location=keyfile")

    with open(key_file) as fd:
        key_contents2 = fd.read()

    assert key_contents2 == key_contents


def test_key_import_keyfile_with_borg_key_file(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)

    exported_key_file = os.path.join(archiver.output_path, "exported")
    cmd(archiver, "key", "export", exported_key_file)

    key_file = os.path.join(archiver.keys_path, os.listdir(archiver.keys_path)[0])
    with open(key_file) as fd:
        key_contents = fd.read()
    os.unlink(key_file)

    imported_key_file = os.path.join(archiver.output_path, "imported")
    monkeypatch.setenv("BORG_KEY_FILE", imported_key_file)
    cmd(archiver, "key", "import", exported_key_file, "--key-location=keyfile")
    assert not os.path.isfile(key_file), '"borg key import" should respect BORG_KEY_FILE'

    with open(imported_key_file) as fd:
        imported_key_contents = fd.read()
    assert imported_key_contents == key_contents


def test_key_export_repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_file = archiver.output_path + "/exported"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "key", "export", export_file)

    with open(export_file) as fd:
        export_contents = fd.read()

    assert is_keyfile(export_contents, bin_to_hex(repo_id))

    with Repository(archiver.repository_path) as repository:
        repo_key = AESOCBKey(repository)  # default storage (repokey): load_any finds the repo's key
        repo_key.load(None, Passphrase.env_passphrase())

    backup_key = AESOCBKey(TestKey.MockRepository(id=repo_id))
    backup_key.storage = KeyBlobStorage.KEYFILE  # load explicitly from the exported keyfile
    backup_key.load(export_file, Passphrase.env_passphrase())

    assert repo_key.crypt_key == backup_key.crypt_key

    with Repository(archiver.repository_path) as repository:
        repository.save_key(b"")

    cmd(archiver, "key", "import", export_file)

    with Repository(archiver.repository_path) as repository:
        repo_key2 = AESOCBKey(repository)
        repo_key2.load(None, Passphrase.env_passphrase())

    assert repo_key2.crypt_key == repo_key.crypt_key


def test_key_export_qr(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_file = archiver.output_path + "/exported.html"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repo_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "key", "export", "--qr-html", export_file)

    with open(export_file, encoding="utf-8") as fd:
        export_contents = fd.read()

    assert bin_to_hex(repo_id) in export_contents
    assert export_contents.startswith("<!doctype html>")
    assert export_contents.endswith("</html>\n")


def test_key_export_directory(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_directory = archiver.output_path + "/exported"
    os.mkdir(export_directory)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        cmd(archiver, "key", "export", export_directory, exit_code=expected_ec)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "key", "export", export_directory)


def test_key_export_qr_directory(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_directory = archiver.output_path + "/exported"
    os.mkdir(export_directory)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        cmd(archiver, "key", "export", "--qr-html", export_directory, exit_code=expected_ec)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "key", "export", "--qr-html", export_directory)


def test_key_import_errors(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_file = archiver.output_path + "/exported"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        cmd(archiver, "key", "import", export_file, exit_code=expected_ec)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "key", "import", export_file)

    with open(export_file, "w") as fd:
        fd.write("something not a key\n")

    if archiver.FORK_DEFAULT:
        expected_ec = NotABorgKeyFile().exit_code
        cmd(archiver, "key", "import", export_file, exit_code=expected_ec)
    else:
        with pytest.raises(NotABorgKeyFile):
            cmd(archiver, "key", "import", export_file)

    with open(export_file, "w") as fd:
        fd.write("BORG_KEY a0a0a0\n")

    if archiver.FORK_DEFAULT:
        expected_ec = RepoIdMismatch().exit_code
        cmd(archiver, "key", "import", export_file, exit_code=expected_ec)
    else:
        with pytest.raises(RepoIdMismatch):
            cmd(archiver, "key", "import", export_file)


def test_key_export_paperkey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_id = "e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239"
    export_file = archiver.output_path + "/exported"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    _set_repository_id(archiver.repository_path, hex_to_bin(repo_id))
    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]

    with open(key_file, "w") as fd:
        fd.write(CHPOKey.FILE_ID + " " + repo_id + "\n")
        fd.write(binascii.b2a_base64(b"abcdefghijklmnopqrstu").decode())

    cmd(archiver, "key", "export", "--paper", export_file)

    with open(export_file) as fd:
        export_contents = fd.read()

    assert (
        export_contents
        == """To restore key use borg key import --paper /path/to/repo

BORG PAPER KEY v1
id: 2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02
 1: 616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d
 2: 737475 - 88
"""
    )


def test_key_import_paperkey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_id = "e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    _set_repository_id(archiver.repository_path, hex_to_bin(repo_id))

    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]
    with open(key_file, "w") as fd:
        fd.write(AESOCBKey.FILE_ID + " " + repo_id + "\n")
        fd.write(binascii.b2a_base64(b"abcdefghijklmnopqrstu").decode())

    typed_input = (
        b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41  02\n"  # Forgot to type "-"
        b"2 / e29442 3506da 4e1ea7  25f62a 5a3d41 - 02\n"  # Forgot to type second "/"
        b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d42 - 02\n"  # Typo (..42 not ..41)
        b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n"  # Correct! Congratulations
        b"616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n"
        b"\n\n"  # Abort [yN] => N
        b"737475 88\n"  # missing "-"
        b"73747i - 88\n"  # typo
        b"73747 - 88\n"  # missing nibble
        b"73 74 75  -  89\n"  # line checksum mismatch
        b"00a1 - 88\n"  # line hash collision - overall hash mismatch, have to start over
        b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n"
        b"616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n"
        b"73 74 75  -  88\n"
    )

    # In case that this has to change, here is a quick way to find a colliding line hash:
    #
    # from hashlib import sha256
    # hash_fn = lambda x: sha256(b'\x00\x02' + x).hexdigest()[:2]
    # for i in range(1000):
    #     if hash_fn(i.to_bytes(2, byteorder='big')) == '88':  # 88 = line hash
    #         print(i.to_bytes(2, 'big'))
    #         break

    cmd(archiver, "key", "import", "--paper", input=typed_input)

    # Test abort paths
    typed_input = b"\ny\n"
    cmd(archiver, "key", "import", "--paper", input=typed_input)
    typed_input = b"2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n\ny\n"
    cmd(archiver, "key", "import", "--paper", input=typed_input)


def test_init_defaults_to_argon2(archivers, request):
    """https://github.com/borgbackup/borg/issues/747#issuecomment-1076160401"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with Repository(archiver.repository_path) as repository:
        key_data = repository.load_key()
        _, key_data = keyfile_parse(key_data, bin_to_hex(repository.id))
        key = msgpack.unpackb(binascii.a2b_base64(key_data))
        assert key["algorithm"] == "argon2 chacha20-poly1305"


def test_change_passphrase_does_not_change_algorithm_argon2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
    cmd(archiver, "key", "change-passphrase")

    with Repository(archiver.repository_path) as repository:
        key_data = repository.load_key()
        _, key_data = keyfile_parse(key_data, bin_to_hex(repository.id))
        key = msgpack.unpackb(binascii.a2b_base64(key_data))
        assert key["algorithm"] == "argon2 chacha20-poly1305"


def test_change_location_does_not_change_algorithm_argon2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    cmd(archiver, "key", "change-location", "repokey")

    with Repository(archiver.repository_path) as repository:
        key_data = repository.load_key()
        if is_keyfile(key_data):
            _, key_data = keyfile_parse(key_data, bin_to_hex(repository.id))
        key = msgpack.unpackb(binascii.a2b_base64(key_data))
        assert key["algorithm"] == "argon2 chacha20-poly1305"


# --- multiple borg keys per repository (borg issue #9743) ---------------------------------------

from ...constants import EXIT_ERROR  # noqa: E402
from ...helpers import Error  # noqa: E402
from ...helpers.passphrase import PassphraseWrong  # noqa: E402

DEFAULT_PASSPHRASE = "waytooeasyonlyfortests"  # see set_env_variables fixture in conftest

# exit code a forking/binary archiver returns for a wrong passphrase. The test env defaults to
# BORG_EXIT_CODES=modern (see helpers/errors.py), so this is the specific PassphraseWrong code, not EXIT_ERROR.
EXIT_PASSPHRASE_WRONG = PassphraseWrong.exit_mcode


def _expect_error(archiver, *args, exit_code=EXIT_ERROR):
    """Assert a borg Error, regardless of whether the archiver forks (exit code) or not (raises)."""
    if archiver.FORK_DEFAULT:
        cmd(archiver, *args, exit_code=exit_code)
    else:
        with pytest.raises(Error):
            cmd(archiver, *args)


def _key_id_for_label(archiver, label):
    """Return the borg key id shown by 'key list' for the given label."""
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    out = cmd(archiver, "key", "list")
    for line in out.splitlines():
        fields = line.split()
        if label in fields:
            for f in fields:
                if len(f) == 12 and all(c in "0123456789abcdef" for c in f):
                    return f
    raise AssertionError(f"label {label!r} not found in:\n{out}")


# crypto suite + key storage combinations used to parametrize the multi-key tests below.
ENC_ARGS_AND_MODE = [((RK_ENCRYPTION,), "repokey"), ((KF_ENCRYPTION, KF_LOCATION), "keyfile")]
ENC_ARGS = [args for args, _mode in ENC_ARGS_AND_MODE]


@pytest.mark.parametrize("enc_args, mode", ENC_ARGS_AND_MODE)
def test_key_first_key_is_admin(archivers, request, enc_args, mode):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", *enc_args)
    out = cmd(archiver, "key", "list")
    assert "admin" in out
    rows = [ln for ln in out.splitlines() if "argon2" in ln]
    assert len(rows) == 1
    assert rows[0].lstrip().startswith("*")
    assert mode in rows[0]


@pytest.mark.parametrize("enc_args", ENC_ARGS)
def test_key_add(archivers, request, enc_args):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", *enc_args)  # admin = DEFAULT_PASSPHRASE
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    out = cmd(archiver, "key", "list")
    rows = [ln for ln in out.splitlines() if "argon2" in ln]
    assert len(rows) == 2
    assert "admin" in out and "alice" in out

    # both borg keys unlock the repository
    os.environ["BORG_PASSPHRASE"] = "alicepass"
    cmd(archiver, "repo-list")
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "repo-list")


def test_key_add_rejects_duplicate_and_reserved(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")
    os.environ["BORG_NEW_PASSPHRASE"] = "otherpass"
    _expect_error(archiver, "key", "add", "--label", "alice")  # duplicate
    _expect_error(archiver, "key", "add", "--label", "admin")  # reserved


@pytest.mark.parametrize("enc_args", ENC_ARGS)
def test_key_remove_by_label(archivers, request, enc_args):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", *enc_args)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "key", "remove", "--label", "alice")

    os.environ["BORG_PASSPHRASE"] = "alicepass"
    _expect_error(archiver, "repo-list", exit_code=EXIT_PASSPHRASE_WRONG)  # alice's passphrase no longer works
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "repo-list")  # admin still works
    out = cmd(archiver, "key", "list")
    assert "alice" not in out and "admin" in out


def test_key_remove_by_id(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    key_id = _key_id_for_label(archiver, "alice")
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "key", "remove", "--key", key_id[:8])

    os.environ["BORG_PASSPHRASE"] = "alicepass"
    _expect_error(archiver, "repo-list", exit_code=EXIT_PASSPHRASE_WRONG)


def test_key_remove_current(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    os.environ["BORG_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "remove", "--passphrase")  # remove the borg key used to unlock
    _expect_error(archiver, "repo-list", exit_code=EXIT_PASSPHRASE_WRONG)  # alice gone
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "repo-list")  # admin remains


def test_key_admin_protected_and_last_key(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    _expect_error(archiver, "key", "remove", "--label", "admin")  # protected, not last
    cmd(archiver, "key", "remove", "--label", "alice")
    _expect_error(archiver, "key", "remove", "--label", "admin")  # now last borg key


def test_key_change_passphrase_only_affects_current_key(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")

    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    os.environ["BORG_NEW_PASSPHRASE"] = "adminpass2"
    cmd(archiver, "key", "change-passphrase")  # rotate admin (we are unlocked as admin)

    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    _expect_error(archiver, "repo-list", exit_code=EXIT_PASSPHRASE_WRONG)  # old admin passphrase fails
    os.environ["BORG_PASSPHRASE"] = "adminpass2"
    cmd(archiver, "repo-list")  # new admin works
    os.environ["BORG_PASSPHRASE"] = "alicepass"
    cmd(archiver, "repo-list")  # alice untouched

    os.environ["BORG_PASSPHRASE"] = "adminpass2"
    out = cmd(archiver, "key", "list")
    rows = [ln for ln in out.splitlines() if "argon2" in ln]
    assert len(rows) == 2
    assert "admin" in out and "alice" in out


def test_key_multiple_keys_share_secrets(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")
    # create an archive unlocked as alice ...
    os.environ["BORG_PASSPHRASE"] = "alicepass"
    cmd(archiver, "create", "arch", archiver.input_path)
    # ... and read it back unlocked as admin (same underlying key material)
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    out = cmd(archiver, "repo-list")
    assert "arch" in out


def test_key_change_location_only_affects_unlocked_key(archivers, request):
    # change-location moves only the borg key we unlocked; the repository's other borg keys
    # (here: alice's repokey) must be left in place, not deleted along with it.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # admin repokey
    os.environ["BORG_NEW_PASSPHRASE"] = "alicepass"
    cmd(archiver, "key", "add", "--label", "alice")  # second repokey

    with Repository(archiver.repository_path) as repository:
        assert len(repository.load_keys()) == 2  # admin + alice

    # change only the unlocked (admin) borg key to keyfile location
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    cmd(archiver, "key", "change-location", "keyfile")

    # admin's repokey is gone from the store, but alice's repokey is untouched
    with Repository(archiver.repository_path) as repository:
        assert len(repository.load_keys()) == 1


def test_key_change_location_keeps_label(archivers, request):
    # change-location must preserve the label of the borg key it migrates.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # admin repokey
    os.environ["BORG_NEW_PASSPHRASE"] = "xxxpass"
    cmd(archiver, "key", "add", "--label", "xxx")  # second repokey, labeled xxx

    # migrate the xxx borg key (unlocked with its own passphrase) from repokey to keyfile
    os.environ["BORG_PASSPHRASE"] = "xxxpass"
    cmd(archiver, "key", "change-location", "keyfile")

    out = cmd(archiver, "key", "list")  # still unlocked as xxx
    # the migrated xxx key now lives in a keyfile; admin stays a repokey (mixed storage is allowed now)
    xxx_rows = [ln for ln in out.splitlines() if "xxx" in ln]
    assert len(xxx_rows) == 1
    assert "keyfile" in xxx_rows[0]  # storage changed
    assert "xxx" in xxx_rows[0]  # label preserved, not lost
    assert "admin" in out  # the other borg key is untouched


def _exported_label(path, repo_id):
    """Return the label stored in the borg key backup written by 'key export'."""
    with open(path) as fd:
        content = fd.read()
    _, b64 = keyfile_parse(content, bin_to_hex(repo_id))
    return msgpack.unpackb(binascii.a2b_base64(b64)).get("label")


def test_key_export_selects_borg_key(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # admin borg key
    os.environ["BORG_NEW_PASSPHRASE"] = "xxxpass"
    cmd(archiver, "key", "add", "--label", "xxx")  # second borg key

    repo_id = _extract_repository_id(archiver.repository_path)
    out_xxx = archiver.output_path + "/xxx"
    out_admin = archiver.output_path + "/admin"

    # more than one borg key and no selector given -> must ask for one
    _expect_error(archiver, "key", "export", out_xxx, exit_code=CommandError().exit_code)

    # selecting by label exports exactly that borg key
    cmd(archiver, "key", "export", "--label", "xxx", out_xxx)
    cmd(archiver, "key", "export", "--label", "admin", out_admin)
    assert _exported_label(out_xxx, repo_id) == "xxx"
    assert _exported_label(out_admin, repo_id) == "admin"

    # selecting the same borg key by id prefix yields the same export
    admin_id = _key_id_for_label(archiver, "admin")
    out_admin2 = archiver.output_path + "/admin2"
    cmd(archiver, "key", "export", "--key", admin_id[:8], out_admin2)
    assert _exported_label(out_admin2, repo_id) == "admin"


def test_key_export_single_key_needs_no_selector(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # only the admin borg key exists
    out = archiver.output_path + "/exported"
    cmd(archiver, "key", "export", out)  # backward compatible: no selector required
    repo_id = _extract_repository_id(archiver.repository_path)
    assert _exported_label(out, repo_id) == "admin"


def test_key_remove_rejects_ambiguous_key_selector(archivers, request):
    # a --key prefix that matches more than one borg key (here: the empty prefix) must be rejected.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "xxxpass"
    cmd(archiver, "key", "add", "--label", "xxx")
    os.environ["BORG_PASSPHRASE"] = DEFAULT_PASSPHRASE
    _expect_error(archiver, "key", "remove", "--key", "")  # matches admin + xxx


def test_key_export_rejects_ambiguous_key_selector(archivers, request):
    # a --key prefix that matches more than one borg key (here: the empty prefix) must be rejected.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "xxxpass"
    cmd(archiver, "key", "add", "--label", "xxx")
    out = archiver.output_path + "/exported"
    _expect_error(archiver, "key", "export", "--key", "", out, exit_code=CommandError().exit_code)


def _store_corrupted_borg_key(repository_path, repo_id):
    """Store a borg key whose envelope is unparseable but which still passes the
    keyfile header / repo-id check (so it is enumerated). Returns its key id."""
    header = CHPOKey.FILE_ID + " " + bin_to_hex(repo_id) + "\n"
    body = binascii.b2a_base64(b"this is not a valid key envelope").decode()  # valid base64, not msgpack
    blob = (header + body).encode("utf-8")
    with Repository(repository_path) as repository:
        return repository.store_key(blob)


def test_key_list_and_remove_corrupted_key(archivers, request):
    # a corrupted borg key must stay visible in "key list" and be removable by its id,
    # instead of being silently dropped (which would make it invisible and unremovable).
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)  # good admin borg key (unlocks the repo)
    repo_id = _extract_repository_id(archiver.repository_path)
    bad_id = _store_corrupted_borg_key(archiver.repository_path, repo_id)

    out = cmd(archiver, "key", "list")
    assert "admin" in out  # the good borg key is listed
    assert bad_id[:12] in out  # the corrupted borg key is still visible

    cmd(archiver, "key", "remove", "--key", bad_id[:12])  # and removable
    out = cmd(archiver, "key", "list")
    assert bad_id[:12] not in out
    assert "admin" in out
