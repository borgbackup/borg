import json

from ...constants import *  # NOQA
from . import checkts, cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION, KF_ENCRYPTION, KF_LOCATION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    info_repo = cmd(archiver, "repo-info")
    assert "Repository ID:" in info_repo


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
