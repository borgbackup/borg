import json
import os

from ...constants import *  # NOQA
from . import cmd, checkts, create_src_archive, create_regular_file, src_dir, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_rlist_glob(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test-1", src_dir)
    cmd(archiver, "create", "something-else-than-test-1", src_dir)
    cmd(archiver, "create", "test-2", src_dir)
    output = cmd(archiver, "rlist", "--match-archives=sh:test-*")
    assert "test-1" in output
    assert "test-2" in output
    assert "something-else" not in output


def test_archives_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "--comment", "comment 1", "test-1", src_dir)
    cmd(archiver, "create", "--comment", "comment 2", "test-2", src_dir)
    output_1 = cmd(archiver, "rlist")
    output_2 = cmd(archiver, "rlist", "--format", "{archive:<36} {time} [{id}]{NL}")
    assert output_1 == output_2
    output_1 = cmd(archiver, "rlist", "--short")
    assert output_1 == "test-1" + os.linesep + "test-2" + os.linesep
    output_3 = cmd(archiver, "rlist", "--format", "{name} {comment}{NL}")
    assert "test-1 comment 1" + os.linesep in output_3
    assert "test-2 comment 2" + os.linesep in output_3


def test_size_nfiles(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=123000)
    create_regular_file(archiver.input_path, "file2", size=456)
    cmd(archiver, "create", "test", "input/file1", "input/file2")
    output = cmd(archiver, "list", "test")
    print(output)
    output = cmd(archiver, "rlist", "--format", "{name} {nfiles} {size}")
    o_t = output.split()
    assert o_t[0] == "test"
    assert int(o_t[1]) == 2
    assert 123456 <= int(o_t[2]) < 123999  # there is some metadata overhead


def test_date_matching(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    earliest_ts = "2022-11-20T23:59:59"
    ts_in_between = "2022-12-18T23:59:59"
    create_src_archive(archiver, "archive1", ts=earliest_ts)
    create_src_archive(archiver, "archive2", ts=ts_in_between)
    create_src_archive(archiver, "archive3")
    cmd(archiver, "rlist", "-v", "--oldest=23e", exit_code=2)

    output = cmd(archiver, "rlist", "-v", "--oldest=1m", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output

    output = cmd(archiver, "rlist", "-v", "--newest=1m", exit_code=0)
    assert "archive3" in output
    assert "archive2" not in output
    assert "archive1" not in output

    output = cmd(archiver, "rlist", "-v", "--newer=1d", exit_code=0)
    assert "archive3" in output
    assert "archive1" not in output
    assert "archive2" not in output

    output = cmd(archiver, "rlist", "-v", "--older=1d", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output


def test_rlist_consider_checkpoints(archivers, request):
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", src_dir)
    # these are not really a checkpoints, but they look like some:
    cmd(archiver, "create", "test2.checkpoint", src_dir)
    cmd(archiver, "create", "test3.checkpoint.1", src_dir)

    output = cmd(archiver, "rlist")
    assert "test1" in output
    assert "test2.checkpoint" not in output
    assert "test3.checkpoint.1" not in output

    output = cmd(archiver, "rlist", "--consider-checkpoints")
    assert "test1" in output
    assert "test2.checkpoint" in output
    assert "test3.checkpoint.1" in output


def test_rlist_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    list_repo = json.loads(cmd(archiver, "rlist", "--json"))
    repository = list_repo["repository"]
    assert len(repository["id"]) == 64
    checkts(repository["last_modified"])
    assert list_repo["encryption"]["mode"] == RK_ENCRYPTION[13:]
    assert "keyfile" not in list_repo["encryption"]
    archive0 = list_repo["archives"][0]
    checkts(archive0["time"])
