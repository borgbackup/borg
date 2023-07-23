import os

import pytest

from ...constants import *  # NOQA
from . import create_regular_file, cmd, RK_ENCRYPTION


@pytest.mark.parametrize("archivers", ["archiver", "remote_archiver", "binary_archiver"])
def test_delete_repo(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path, input_path = archiver.repository_location, archiver.repository_path, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "dir2/file2", size=1024 * 80)

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test.2", "input")
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "no"
    cmd(archiver, f"--repo={repo_location}", "rdelete", exit_code=2)
    assert os.path.exists(repo_path)
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    cmd(archiver, f"--repo={repo_location}", "rdelete")
    # Make sure the repo is gone
    assert not os.path.exists(repo_path)
