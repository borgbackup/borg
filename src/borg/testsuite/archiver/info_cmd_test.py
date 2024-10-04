import json
import os

from ...constants import *  # NOQA
from . import cmd, checkts, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    info_archive = cmd(archiver, "info", "-a", "test")
    assert "Archive name: test" + os.linesep in info_archive
    info_archive = cmd(archiver, "info", "--first", "1")
    assert "Archive name: test" + os.linesep in info_archive


def test_info_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    info_archive = json.loads(cmd(archiver, "info", "-a", "test", "--json"))
    archives = info_archive["archives"]
    assert len(archives) == 1
    archive = archives[0]
    assert archive["name"] == "test"
    assert isinstance(archive["command_line"], str)
    assert isinstance(archive["duration"], float)
    assert len(archive["id"]) == 64
    assert archive["tags"] == []
    assert "stats" in archive
    checkts(archive["start"])
    checkts(archive["end"])


def test_info_json_of_empty_archive(archivers, request):
    """See https://github.com/borgbackup/borg/issues/6120"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    info_repo = json.loads(cmd(archiver, "info", "--json", "--first=1"))
    assert info_repo["archives"] == []
    info_repo = json.loads(cmd(archiver, "info", "--json", "--last=1"))
    assert info_repo["archives"] == []
