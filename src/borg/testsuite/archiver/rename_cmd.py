import pytest

from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, create_regular_file, RK_ENCRYPTION


@pytest.mark.parametrize("archivers", ["archiver", "remote_archiver", "binary_archiver"])
def test_rename(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path, input_path = archiver.repository_location, archiver.repository_path, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    create_regular_file(input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    cmd(archiver, f"--repo={repo_location}", "create", "test.2", "input")
    cmd(archiver, f"--repo={repo_location}", "extract", "test", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "rename", "test", "test.3")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.2", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "rename", "test.2", "test.4")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.3", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "extract", "test.4", "--dry-run")
    # Make sure both archives have been renamed
    with Repository(repo_path) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
    assert len(manifest.archives) == 2
    assert "test.3" in manifest.archives
    assert "test.4" in manifest.archives
