import json
import os

import pytest

from ...constants import *  # NOQA
from ...repository import Repository
from . import cmd, checkts, create_regular_file, generate_archiver_tests, RK_ENCRYPTION
from .prune_cmd_test import _create_archive_ts

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_repo_list_glob(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", backup_files)
    cmd(archiver, "create", "something-else-than-test-1", backup_files)
    cmd(archiver, "create", "test-2", backup_files)
    output = cmd(archiver, "repo-list", "--match-archives=sh:test-*")
    assert "test-1" in output
    assert "test-2" in output
    assert "something-else" not in output


def test_repo_list_exclude_archives(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", backup_files)
    cmd(archiver, "create", "test-2", backup_files)
    cmd(archiver, "create", "other-1", backup_files)
    output = cmd(archiver, "repo-list", "--exclude-archives=sh:test-*")
    assert "test-1" not in output
    assert "test-2" not in output
    assert "other-1" in output


def test_repo_list_exclude_archives_multiple(archivers, request, backup_files):
    # several exclusion patterns are ORed: an archive matching any of them is skipped
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", backup_files)
    cmd(archiver, "create", "test-2", backup_files)
    cmd(archiver, "create", "test-3", backup_files)
    output = cmd(archiver, "repo-list", "--exclude-archives=test-1", "--exclude-archives=test-3")
    assert "test-1" not in output
    assert "test-2" in output
    assert "test-3" not in output


def test_repo_list_match_and_exclude_archives(archivers, request, backup_files):
    # an archive is considered if it matches all --match-archives and none of the --exclude-archives
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", backup_files)
    cmd(archiver, "create", "test-2", backup_files)
    cmd(archiver, "create", "other-1", backup_files)
    output = cmd(archiver, "repo-list", "--match-archives=sh:test-*", "--exclude-archives=test-2")
    assert "test-1" in output
    assert "test-2" not in output
    assert "other-1" not in output


def test_repo_list_exclude_archives_by_tag(archivers, request, backup_files):
    # exclusion accepts the same selector prefixes as --match-archives, not just names
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--tags", "keepme", "--", "test-1", backup_files)
    cmd(archiver, "create", "test-2", backup_files)
    output = cmd(archiver, "repo-list", "--exclude-archives=tags:keepme")
    assert "test-1" not in output
    assert "test-2" in output


def test_archives_format(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--comment", "comment 1", "test-1", backup_files)
    cmd(archiver, "create", "--comment", "comment 2", "test-2", backup_files)
    output_1 = cmd(archiver, "repo-list")
    output_2 = cmd(
        archiver,
        "repo-list",
        "--format",
        "{id:.8}  {time}  {archive:<15}  {tags:<10}  {username:<10}  {hostname:<10}  {comment:.40}{NL}",
    )
    assert output_1 == output_2
    output = cmd(archiver, "repo-list", "--short")
    assert len(output) == 2 * 64 + 2 * len(os.linesep)
    output = cmd(archiver, "repo-list", "--format", "{name} {comment}{NL}")
    assert "test-1 comment 1" + os.linesep in output
    assert "test-2 comment 2" + os.linesep in output


def test_repo_list_does_not_read_item_metadata(archiver, monkeypatch):
    # listing a repository only needs the archive metadata objects, never the item metadata
    # streams the archives point to. reading those means reading the item_ptrs chunks, which
    # sit in the (potentially large) data packs -- expensive for remote repositories, see #10204.
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "test", "input")
    get_many_calls = []
    original_get_many = Repository.get_many

    def get_many(self, ids, *args, **kwargs):
        ids = list(ids)
        get_many_calls.append(ids)
        return original_get_many(self, ids, *args, **kwargs)

    monkeypatch.setattr(Repository, "get_many", get_many)
    output = cmd(archiver, "repo-list")
    assert "test" in output
    assert get_many_calls == []


def test_size_nfiles(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=123000)
    create_regular_file(archiver.input_path, "file2", size=456)
    cmd(archiver, "create", "test", "input/file1", "input/file2")
    output = cmd(archiver, "list", "test")
    print(output)
    output = cmd(archiver, "repo-list", "--format", "{name} {nfiles} {size}")
    o_t = output.split()
    assert o_t[0] == "test"
    assert int(o_t[1]) == 2
    assert 123456 <= int(o_t[2]) < 123999  # There is some metadata overhead


def test_date_matching(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    _create_archive_ts(archiver, backup_files, "archive-2022-11-20", 2022, 11, 20, 23, 59, 59)
    _create_archive_ts(archiver, backup_files, "archive-2022-12-18", 2022, 12, 18, 23, 59, 59)
    cmd(archiver, "create", "archive-now", backup_files)

    cmd(archiver, "check", "-v", "--oldest=23e", exit_code=2)

    output = cmd(archiver, "repo-list", "-v", "--oldest=1y", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newest=1y", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--oldest=1m", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newest=1m", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--oldest=4w", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newest=4w", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--newer=1d", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--older=1d", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newer=24H", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--older=24H", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newer=1440M", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--older=1440M", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "repo-list", "-v", "--newer=86400S", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "repo-list", "-v", "--older=86400S", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output


def test_repo_list_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    list_repo = json.loads(cmd(archiver, "repo-list", "--json"))
    repository = list_repo["repository"]
    assert len(repository["id"]) == 64
    checkts(repository["last_modified"])
    assert list_repo["encryption"]["encryption"] == RK_ENCRYPTION[13:]  # --encryption=aes256-ocb
    assert list_repo["encryption"]["id_hash"] == "sha256"  # default id-hash
    assert "keyfile" not in list_repo["encryption"]
    archive0 = list_repo["archives"][0]
    checkts(archive0["time"])


def test_repo_list_deleted(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "normal1", backup_files)
    cmd(archiver, "create", "deleted1", backup_files)
    cmd(archiver, "create", "normal2", backup_files)
    cmd(archiver, "create", "deleted2", backup_files)
    cmd(archiver, "delete", "-a", "sh:deleted*")
    output = cmd(archiver, "repo-list")
    assert "normal1" in output
    assert "normal2" in output
    assert "deleted1" not in output
    assert "deleted2" not in output
    output = cmd(archiver, "repo-list", "--deleted")
    assert "normal1" not in output
    assert "normal2" not in output
    assert "deleted1" in output
    assert "deleted2" in output


def test_repo_list_from_borg1(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() in ["remote", "binary"]:
        pytest.skip("only works locally")

    import tarfile

    repo12_tar = os.path.join(os.path.dirname(__file__), "repo12.tar.gz")
    original_location = archiver.repository_location
    extract_dir = f"{original_location}1"
    os.makedirs(extract_dir)
    with tarfile.open(repo12_tar) as tf:
        tf.extractall(extract_dir)

    monkeypatch.setenv("BORG_PASSPHRASE", "waytooeasyonlyfortests")
    monkeypatch.setenv("BORG_TESTONLY_WEAKEN_KDF", "0")

    # Set repository location to the extracted Borg 1.x repository
    archiver.repository_location = extract_dir
    archiver.repository_path = extract_dir

    output = cmd(archiver, "repo-list", "--from-borg1")
    assert "archive1" in output
    assert "archive2" in output


def _create_shared_repo_archives(archiver, backup_files, monkeypatch):
    """host1 has a "home" and an "etc" archive, host2 has an own, unrelated "home" archive."""
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("BORG_HOSTNAME", "host1")
    cmd(archiver, "create", "home", backup_files)
    cmd(archiver, "create", "etc", backup_files)
    monkeypatch.setenv("BORG_HOSTNAME", "host2")
    cmd(archiver, "create", "home", backup_files)
    monkeypatch.delenv("BORG_HOSTNAME")


def test_repo_list_group_by(archivers, request, backup_files, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    _create_shared_repo_archives(archiver, backup_files, monkeypatch)
    output = cmd(archiver, "repo-list", "--group-by", "name,host", "--format", "{archive} {hostname}{NL}")
    assert output.splitlines() == [
        "Group (name='home', host='host1'):",
        "home host1",
        "",
        "Group (name='etc', host='host1'):",
        "etc host1",
        "",
        "Group (name='home', host='host2'):",
        "home host2",
    ]


def test_repo_list_group_by_single_key(archivers, request, backup_files, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    _create_shared_repo_archives(archiver, backup_files, monkeypatch)
    output = cmd(archiver, "repo-list", "--group-by", "name", "--format", "{archive} {hostname}{NL}")
    # both hosts' "home" archives are in one group now:
    assert output.splitlines() == [
        "Group (name='home'):",
        "home host1",
        "home host2",
        "",
        "Group (name='etc'):",
        "etc host1",
    ]


def test_repo_list_without_group_by_is_unchanged(archivers, request, backup_files, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    _create_shared_repo_archives(archiver, backup_files, monkeypatch)
    output = cmd(archiver, "repo-list", "--format", "{archive} {hostname}{NL}")
    assert output.splitlines() == ["home host1", "etc host1", "home host2"]
    assert "Group (" not in output


def test_repo_list_group_by_json(archivers, request, backup_files, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    _create_shared_repo_archives(archiver, backup_files, monkeypatch)
    archives = json.loads(cmd(archiver, "repo-list", "--group-by", "name,host", "--json"))["archives"]
    assert [archive["group"] for archive in archives] == [
        {"name": "home", "host": "host1"},
        {"name": "etc", "host": "host1"},
        {"name": "home", "host": "host2"},
    ]
    # no grouping requested, no group in the output:
    archives = json.loads(cmd(archiver, "repo-list", "--json"))["archives"]
    assert all("group" not in archive for archive in archives)


def test_repo_list_group_by_invalid_key(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "repo-list", "--group-by", "bogus", exit_code=2)
    assert "Invalid group-by key: bogus" in output
