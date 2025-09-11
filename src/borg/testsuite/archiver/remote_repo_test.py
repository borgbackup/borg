import os
import pytest

from . import cmd, create_regular_file, RK_ENCRYPTION


SFTP_URL = os.environ.get("BORG_TEST_SFTP_REPO")


@pytest.mark.skipif(not SFTP_URL, reason="BORG_TEST_SFTP_REPO not set.")
def test_sftp_repo_basics(archiver):
    # Point the archiver to the externally provided SFTP repository URL
    archiver.repository_location = SFTP_URL

    # Ensure input exists and create a small file to back up
    create_regular_file(archiver.input_path, "file1", size=100 * 1024)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    archive_name = "test-archive"
    cmd(archiver, "create", archive_name, "input")
    list_output = cmd(archiver, "repo-list")
    assert archive_name in list_output
    cmd(archiver, "delete", "-a", archive_name)
    list_output = cmd(archiver, "repo-list")
    assert archive_name not in list_output
    cmd(archiver, "repo-delete")
