import json

from ...constants import *  # NOQA
from . import checkts, cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION, KF_ENCRYPTION, KF_LOCATION
from . import set_empty_passphrase

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    info_repo = cmd(archiver, "repo-info")
    assert "Repository ID:" in info_repo
    assert "Encrypted: Yes (repokey, aes256-ocb, sha256)" in info_repo
    assert "empty passphrase" not in info_repo


def test_info_empty_passphrase_repokey(archivers, request, monkeypatch):
    # an empty passphrase is shown in the Encrypted: line, see #9072
    archiver = request.getfixturevalue(archivers)
    set_empty_passphrase(monkeypatch)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    info_repo = cmd(archiver, "repo-info")
    assert "Encrypted: Yes (repokey, aes256-ocb, sha256, empty passphrase)" in info_repo
    # after setting a passphrase, the note is gone
    monkeypatch.setenv("BORG_NEW_PASSPHRASE", "secret")
    cmd(archiver, "key", "change-passphrase")
    monkeypatch.delenv("BORG_NEW_PASSPHRASE")
    monkeypatch.delenv("BORG_PASSCOMMAND")
    monkeypatch.setenv("BORG_PASSPHRASE", "secret")
    info_repo = cmd(archiver, "repo-info")
    assert "Encrypted: Yes (repokey, aes256-ocb, sha256)" in info_repo
    assert "empty passphrase" not in info_repo


def test_info_empty_passphrase_keyfile(archivers, request, monkeypatch):
    # also shown for keyfile storage (where an empty passphrase can be a legitimate choice), see #9072
    archiver = request.getfixturevalue(archivers)
    set_empty_passphrase(monkeypatch)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    info_repo = cmd(archiver, "repo-info")
    assert "Encrypted: Yes (keyfile, chacha20-poly1305, sha256, empty passphrase)" in info_repo
    assert "Key file: " in info_repo


def test_info_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    info_repo = json.loads(cmd(archiver, "repo-info", "--json"))
    repository = info_repo["repository"]
    assert len(repository["id"]) == 64
    assert "last_modified" in repository

    checkts(repository["last_modified"])
    assert info_repo["encryption"]["encryption"] == RK_ENCRYPTION[13:]  # --encryption=aes256-ocb
    assert info_repo["encryption"]["id_hash"] == "sha256"  # default id-hash
    assert "keyfile" not in info_repo["encryption"]  # repokey storage -> no keyfile path


def test_info_json_keyfile(archivers, request):
    # for keyfile storage, --json reports the local key file path under encryption.keyfile
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)

    info_repo = json.loads(cmd(archiver, "repo-info", "--json"))
    keyfile = info_repo["encryption"]["keyfile"]
    assert keyfile  # a (non-empty) path string to the local key file
