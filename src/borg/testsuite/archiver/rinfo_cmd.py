import json
from random import randbytes

from ...constants import *  # NOQA
from . import checkts, cmd, create_regular_file, RK_ENCRYPTION


def pytest_generate_tests(metafunc):
    # Generate tests for different scenarios: local repository, remote repository, and using the borg binary.
    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", ["archiver", "remote_archiver", "binary_archiver"])


def test_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    info_repo = cmd(archiver, f"--repo={repo_location}", "rinfo")
    assert "Original size:" in info_repo


def test_info_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    info_repo = json.loads(cmd(archiver, f"--repo={repo_location}", "rinfo", "--json"))
    repository = info_repo["repository"]
    assert len(repository["id"]) == 64
    assert "last_modified" in repository

    checkts(repository["last_modified"])
    assert info_repo["encryption"]["mode"] == RK_ENCRYPTION[13:]
    assert "keyfile" not in info_repo["encryption"]

    cache = info_repo["cache"]
    stats = cache["stats"]
    assert all(isinstance(o, int) for o in stats.values())
    assert all(key in stats for key in ("total_chunks", "total_size", "total_unique_chunks", "unique_size"))


def test_info_on_repository_with_storage_quota(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", contents=randbytes(1000 * 1000))

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION, "--storage-quota=1G")
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    info_repo = cmd(archiver, f"--repo={repo_location}", "rinfo")
    assert "Storage quota: 1.00 MB used out of 1.00 GB" in info_repo


def test_info_on_repository_without_storage_quota(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", contents=randbytes(1000 * 1000))

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    info_repo = cmd(archiver, f"--repo={repo_location}", "rinfo")
    assert "Storage quota: 1.00 MB used" in info_repo
