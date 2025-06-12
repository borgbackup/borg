import binascii
import os

import pytest

from ...constants import *  # NOQA
from ...crypto.key import AESOCBRepoKey, AESOCBKeyfileKey, CHPOKeyfileKey, Passphrase
from ...crypto.keymanager import RepoIdMismatch, NotABorgKeyFile
from ...helpers import CommandError
from ...helpers import bin_to_hex, hex_to_bin
from ...helpers import msgpack
from ...repository import Repository
from ..crypto.key_test import TestKey
from . import RK_ENCRYPTION, KF_ENCRYPTION, cmd, _extract_repository_id, _set_repository_id, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_change_passphrase(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
    # here we have both BORG_PASSPHRASE and BORG_NEW_PASSPHRASE set:
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
    assert "(key file" in log


def test_change_location_to_b2keyfile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=repokey-blake2-aes-ocb")
    log = cmd(archiver, "repo-info")
    assert "(repokey BLAKE2b" in log
    cmd(archiver, "key", "change-location", "keyfile")
    log = cmd(archiver, "repo-info")
    assert "(key file BLAKE2b" in log


def test_change_location_to_repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    log = cmd(archiver, "repo-info")
    assert "(key file" in log
    cmd(archiver, "key", "change-location", "repokey")
    log = cmd(archiver, "repo-info")
    assert "(repokey" in log


def test_change_location_to_b2repokey(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=keyfile-blake2-aes-ocb")
    log = cmd(archiver, "repo-info")
    assert "(key file BLAKE2b" in log
    cmd(archiver, "key", "change-location", "repokey")
    log = cmd(archiver, "repo-info")
    assert "(repokey BLAKE2b" in log


def test_key_export_keyfile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    export_file = archiver.output_path + "/exported"
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    repo_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "key", "export", export_file)

    with open(export_file) as fd:
        export_contents = fd.read()

    assert export_contents.startswith("BORG_KEY " + bin_to_hex(repo_id) + "\n")

    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]

    with open(key_file) as fd:
        key_contents = fd.read()

    assert key_contents == export_contents

    os.unlink(key_file)

    cmd(archiver, "key", "import", export_file)

    with open(key_file) as fd:
        key_contents2 = fd.read()

    assert key_contents2 == key_contents


def test_key_import_keyfile_with_borg_key_file(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION)

    exported_key_file = os.path.join(archiver.output_path, "exported")
    cmd(archiver, "key", "export", exported_key_file)

    key_file = os.path.join(archiver.keys_path, os.listdir(archiver.keys_path)[0])
    with open(key_file) as fd:
        key_contents = fd.read()
    os.unlink(key_file)

    imported_key_file = os.path.join(archiver.output_path, "imported")
    monkeypatch.setenv("BORG_KEY_FILE", imported_key_file)
    cmd(archiver, "key", "import", exported_key_file)
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

    assert export_contents.startswith("BORG_KEY " + bin_to_hex(repo_id) + "\n")

    with Repository(archiver.repository_path) as repository:
        repo_key = AESOCBRepoKey(repository)
        repo_key.load(None, Passphrase.env_passphrase())

    backup_key = AESOCBKeyfileKey(TestKey.MockRepository())
    backup_key.load(export_file, Passphrase.env_passphrase())

    assert repo_key.crypt_key == backup_key.crypt_key

    with Repository(archiver.repository_path) as repository:
        repository.save_key(b"")

    cmd(archiver, "key", "import", export_file)

    with Repository(archiver.repository_path) as repository:
        repo_key2 = AESOCBRepoKey(repository)
        repo_key2.load(None, Passphrase.env_passphrase())

    assert repo_key2.crypt_key == repo_key2.crypt_key


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
    cmd(archiver, "repo-create", KF_ENCRYPTION)
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
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    _set_repository_id(archiver.repository_path, hex_to_bin(repo_id))
    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]

    with open(key_file, "w") as fd:
        fd.write(CHPOKeyfileKey.FILE_ID + " " + repo_id + "\n")
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
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    _set_repository_id(archiver.repository_path, hex_to_bin(repo_id))

    key_file = archiver.keys_path + "/" + os.listdir(archiver.keys_path)[0]
    with open(key_file, "w") as fd:
        fd.write(AESOCBKeyfileKey.FILE_ID + " " + repo_id + "\n")
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
        key = msgpack.unpackb(binascii.a2b_base64(repository.load_key()))
        assert key["algorithm"] == "argon2 chacha20-poly1305"


def test_change_passphrase_does_not_change_algorithm_argon2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    os.environ["BORG_NEW_PASSPHRASE"] = "newpassphrase"
    cmd(archiver, "key", "change-passphrase")

    with Repository(archiver.repository_path) as repository:
        key = msgpack.unpackb(binascii.a2b_base64(repository.load_key()))
        assert key["algorithm"] == "argon2 chacha20-poly1305"


def test_change_location_does_not_change_algorithm_argon2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION)
    cmd(archiver, "key", "change-location", "repokey")

    with Repository(archiver.repository_path) as repository:
        key = msgpack.unpackb(binascii.a2b_base64(repository.load_key()))
        assert key["algorithm"] == "argon2 chacha20-poly1305"
