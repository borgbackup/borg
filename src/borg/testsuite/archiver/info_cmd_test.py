import json
import os

from ...constants import *  # NOQA
from .. import changedir
from . import cmd, checkts, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


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
    """See https://github.com/borgbackup/borg/issues/6120."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    info_repo = json.loads(cmd(archiver, "info", "--json", "--first=1"))
    assert info_repo["archives"] == []
    info_repo = json.loads(cmd(archiver, "info", "--json", "--last=1"))
    assert info_repo["archives"] == []


def test_info_working_directory(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # create a file in input and create the archive from inside the input directory
    create_regular_file(archiver.input_path, "file1", size=1)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    expected_cwd = os.path.abspath(archiver.input_path)
    with changedir(archiver.input_path):
        cmd(archiver, "create", "test", ".")
    info_archive = cmd(archiver, "info", "-a", "test")
    assert f"Working Directory: {expected_cwd}" in info_archive


def test_info_name_with_aid_prefix(archivers, request, monkeypatch):
    """NAME is used as-is, so the aid: selector prefix works there and combines with -a."""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("BORG_HOSTNAME", "host1")
    cmd(archiver, "create", "home", "input")
    monkeypatch.delenv("BORG_HOSTNAME")
    archive_id = json.loads(cmd(archiver, "repo-list", "--json"))["archives"][0]["id"]
    info = json.loads(cmd(archiver, "info", "--json", f"aid:{archive_id[:8]}"))
    assert info["archives"][0]["id"] == archive_id
    # an aid: NAME is ANDed with -a like any other pattern:
    info = json.loads(cmd(archiver, "info", "--json", f"aid:{archive_id[:8]}", "-a", "host:host1"))
    assert info["archives"][0]["id"] == archive_id
