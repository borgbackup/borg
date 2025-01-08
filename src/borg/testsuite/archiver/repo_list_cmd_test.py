import json
import os

from ...constants import *  # NOQA
from . import cmd, checkts, create_src_archive, create_regular_file, src_dir, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_repo_list_glob(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", src_dir)
    cmd(archiver, "create", "something-else-than-test-1", src_dir)
    cmd(archiver, "create", "test-2", src_dir)
    output = cmd(archiver, "repo-list", "--match-archives=sh:test-*")
    assert "test-1" in output
    assert "test-2" in output
    assert "something-else" not in output


def test_archives_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--comment", "comment 1", "test-1", src_dir)
    cmd(archiver, "create", "--comment", "comment 2", "test-2", src_dir)
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
    assert 123456 <= int(o_t[2]) < 123999  # there is some metadata overhead


def test_date_matching(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    create_src_archive(archiver, "archive-2022-11-20", ts="2022-11-20T23:59:59")
    create_src_archive(archiver, "archive-2022-12-18", ts="2022-12-18T23:59:59")
    create_src_archive(archiver, "archive-now")

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
    assert list_repo["encryption"]["mode"] == RK_ENCRYPTION[13:]
    assert "keyfile" not in list_repo["encryption"]
    archive0 = list_repo["archives"][0]
    checkts(archive0["time"])


def test_repo_list_deleted(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "normal1", src_dir)
    cmd(archiver, "create", "deleted1", src_dir)
    cmd(archiver, "create", "normal2", src_dir)
    cmd(archiver, "create", "deleted2", src_dir)
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
