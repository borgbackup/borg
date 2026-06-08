import json
import os
import shutil
import subprocess
import sys

import pytest

from .. import changedir
from . import cmd, create_regular_file, RK_ENCRYPTION, assert_dirs_equal


SFTP_URL = os.environ.get("BORG_TEST_SFTP_REPO")
REST_URL = os.environ.get("BORG_TEST_REST_REPO")
S3_URL = os.environ.get("BORG_TEST_S3_REPO")


def have_rclone():
    rclone_path = shutil.which("rclone")
    if not rclone_path:
        return False  # not installed
    try:
        # rclone returns JSON for core/version, e.g. {"decomposed": [1,59,2], "version": "v1.59.2"}
        out = subprocess.check_output([rclone_path, "rc", "--loopback", "core/version"])
        info = json.loads(out.decode("utf-8"))
    except Exception:
        return False
    try:
        if info.get("decomposed", []) < [1, 57, 0]:
            return False  # too old
    except Exception:
        return False
    return True  # looks good


@pytest.mark.skipif(not have_rclone(), reason="rclone must be installed for this test.")
def test_rclone_repo_basics(archiver, tmp_path):
    create_regular_file(archiver.input_path, "file1", size=100 * 1024)
    create_regular_file(archiver.input_path, "file2", size=10 * 1024)
    rclone_repo_dir = tmp_path / "rclone-repo"
    os.makedirs(rclone_repo_dir, exist_ok=True)
    archiver.repository_location = f"rclone:{os.fspath(rclone_repo_dir)}"
    archive_name = "test-archive"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", archive_name, "input")
    list_output = cmd(archiver, "repo-list")
    assert archive_name in list_output
    archive_list_output = cmd(archiver, "list", archive_name)
    assert "input/file1" in archive_list_output
    assert "input/file2" in archive_list_output
    with changedir("output"):
        cmd(archiver, "extract", archive_name)
    assert_dirs_equal(
        archiver.input_path, os.path.join(archiver.output_path, "input"), ignore_flags=True, ignore_xattrs=True
    )
    cmd(archiver, "delete", "-a", archive_name)
    list_output = cmd(archiver, "repo-list")
    assert archive_name not in list_output
    cmd(archiver, "repo-delete")


@pytest.mark.skipif(not REST_URL, reason="BORG_TEST_REST_REPO not set.")
def test_rest_repo_basics(archiver, monkeypatch):
    create_regular_file(archiver.input_path, "file1", size=100 * 1024)
    create_regular_file(archiver.input_path, "file2", size=10 * 1024)
    # A rest:// repo over ssh starts "borg serve --rest" on the remote. For this test the remote is
    # localhost (see CI BORG_TEST_REST_REPO), so point BORG_REMOTE_PATH at the borg under test
    # (an absolute path that is valid locally) unless the caller already set it.
    if not os.environ.get("BORG_REMOTE_PATH"):
        borg_path = shutil.which("borg") or os.path.join(os.path.dirname(sys.executable), "borg")
        if os.path.exists(borg_path):
            monkeypatch.setenv("BORG_REMOTE_PATH", borg_path)
    archiver.repository_location = REST_URL
    archive_name = "test-archive"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", archive_name, "input")
    list_output = cmd(archiver, "repo-list")
    assert archive_name in list_output
    archive_list_output = cmd(archiver, "list", archive_name)
    assert "input/file1" in archive_list_output
    assert "input/file2" in archive_list_output
    with changedir("output"):
        cmd(archiver, "extract", archive_name)
    assert_dirs_equal(
        archiver.input_path, os.path.join(archiver.output_path, "input"), ignore_flags=True, ignore_xattrs=True
    )
    cmd(archiver, "delete", "-a", archive_name)
    list_output = cmd(archiver, "repo-list")
    assert archive_name not in list_output
    cmd(archiver, "repo-delete")


@pytest.mark.skipif(not SFTP_URL, reason="BORG_TEST_SFTP_REPO not set.")
def test_sftp_repo_basics(archiver):
    create_regular_file(archiver.input_path, "file1", size=100 * 1024)
    create_regular_file(archiver.input_path, "file2", size=10 * 1024)
    archiver.repository_location = SFTP_URL
    archive_name = "test-archive"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", archive_name, "input")
    list_output = cmd(archiver, "repo-list")
    assert archive_name in list_output
    archive_list_output = cmd(archiver, "list", archive_name)
    assert "input/file1" in archive_list_output
    assert "input/file2" in archive_list_output
    with changedir("output"):
        cmd(archiver, "extract", archive_name)
    assert_dirs_equal(
        archiver.input_path, os.path.join(archiver.output_path, "input"), ignore_flags=True, ignore_xattrs=True
    )
    cmd(archiver, "delete", "-a", archive_name)
    list_output = cmd(archiver, "repo-list")
    assert archive_name not in list_output
    cmd(archiver, "repo-delete")


@pytest.mark.skipif(not S3_URL, reason="BORG_TEST_S3_REPO not set.")
def test_s3_repo_basics(archiver):
    create_regular_file(archiver.input_path, "file1", size=100 * 1024)
    create_regular_file(archiver.input_path, "file2", size=10 * 1024)
    archiver.repository_location = S3_URL
    archive_name = "test-archive"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", archive_name, "input")
    list_output = cmd(archiver, "repo-list")
    assert archive_name in list_output
    archive_list_output = cmd(archiver, "list", archive_name)
    assert "input/file1" in archive_list_output
    assert "input/file2" in archive_list_output
    with changedir("output"):
        cmd(archiver, "extract", archive_name)
    assert_dirs_equal(
        archiver.input_path, os.path.join(archiver.output_path, "input"), ignore_flags=True, ignore_xattrs=True
    )
    cmd(archiver, "delete", "-a", archive_name)
    list_output = cmd(archiver, "repo-list")
    assert archive_name not in list_output
    cmd(archiver, "repo-delete")
