import json
import os

from ...constants import *  # NOQA
from . import cmd, checkts, create_regular_file, RK_ENCRYPTION
from . import pytest_generate_tests  # NOQA


def test_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    info_archive = cmd(archiver, f"--repo={repo_location}", "info", "-a", "test")
    assert "Archive name: test" + os.linesep in info_archive
    info_archive = cmd(archiver, f"--repo={repo_location}", "info", "--first", "1")
    assert "Archive name: test" + os.linesep in info_archive


def test_info_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")

    info_archive = json.loads(cmd(archiver, f"--repo={repo_location}", "info", "-a", "test", "--json"))
    archives = info_archive["archives"]
    assert len(archives) == 1
    archive = archives[0]
    assert archive["name"] == "test"
    assert isinstance(archive["command_line"], str)
    assert isinstance(archive["duration"], float)
    assert len(archive["id"]) == 64
    assert "stats" in archive
    checkts(archive["start"])
    checkts(archive["end"])


def test_info_json_of_empty_archive(archivers, request):
    """See https://github.com/borgbackup/borg/issues/6120"""
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    info_repo = json.loads(cmd(archiver, f"--repo={repo_location}", "info", "--json", "--first=1"))
    assert info_repo["archives"] == []
    info_repo = json.loads(cmd(archiver, f"--repo={repo_location}", "info", "--json", "--last=1"))
    assert info_repo["archives"] == []
