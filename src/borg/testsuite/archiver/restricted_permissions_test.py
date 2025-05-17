import os
import pytest

from borgstore.backends.errors import PermissionDenied

from ...constants import *  # NOQA
from .. import changedir
from . import cmd, create_test_files, RK_ENCRYPTION, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def test_repository_permissions_all(archivers, request, monkeypatch):
    """Test repository with 'all' permissions setting"""
    archiver = request.getfixturevalue(archivers)

    # Create a repository with unrestricted permissions.
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "all")
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    create_test_files(archiver.input_path)
    cmd(archiver, "create", "archive1", "input")

    # Verify the archive was created.
    assert "archive1" in cmd(archiver, "repo-list")

    # Delete the archive to verify unrestricted permissions.
    cmd(archiver, "delete", "archive1")

    # Verify the archive was deleted.
    assert "archive1" not in cmd(archiver, "repo-list")

    # Delete the repository to verify unrestricted permissions.
    cmd(archiver, "repo-delete")


def test_repository_permissions_no_delete(archivers, request, monkeypatch):
    """Test repository with 'no-delete' permissions setting"""
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)

    # Create a repository first (need unrestricted permissions for that).
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "all")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    cmd(archiver, "delete", "archive1")  # this is so that compact has some chunk to remove

    # Switch to no-delete permissions.
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "no-delete")

    # Creating new archives should work.
    cmd(archiver, "create", "archive2", "input")

    # Verify the archive was created.
    assert "archive2" in cmd(archiver, "repo-list")

    # Try to delete the archive, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "delete", "archive2")

    # Verify the archive still exists.
    assert "archive2" in cmd(archiver, "repo-list")

    # Try to rename an archive, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "rename", "archive2", "archive3")

    # Verify the archive still exists.
    assert "archive2" in cmd(archiver, "repo-list")

    # Try to delete the repo, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "repo-delete")

    # Verify the archive still exists.
    assert "archive2" in cmd(archiver, "repo-list")

    # Try to compact the repo, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "compact")

    # Check without --repair should work.
    cmd(archiver, "check")

    # Try to check --repair, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "check", "--repair")

    # Try to repo-compress (and change compression from lz4 to zstd), which should fail.
    # It fails because it needs to overwrite existing chunks, which is also disallowed by no-delete.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "repo-compress", "-C", "zstd")


def test_repository_permissions_read_only(archivers, request, monkeypatch):
    """Test repository with 'read-only' permissions setting"""
    archiver = request.getfixturevalue(archivers)

    # Create a repository first (need unrestricted permissions for that).
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "all")
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Create an archive to test with.
    create_test_files(archiver.input_path)
    cmd(archiver, "create", "archive2", "input")

    # Switch to read-only permissions.
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "read-only")

    # Verify we can list archives.
    assert "archive2" in cmd(archiver, "repo-list")

    # Verify we can list files in an archive.
    assert "input/" in cmd(archiver, "list", "archive2")

    # Extract the archive.
    with changedir("output"):
        cmd(archiver, "extract", "archive2")

    # Verify extraction worked.
    extracted_files = os.listdir("output")
    assert len(extracted_files) > 0

    # Try to create a new archive, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "create", "archive3", "input")

    # Try to delete an archive, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "delete", "archive2")

    # Try to delete the repo, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "repo-delete")

    # Try to compact the repo, which should fail.
    with pytest.raises(PermissionDenied):
        cmd(archiver, "compact")


def test_repository_permissions_write_only(archivers, request, monkeypatch):
    """Test repository with 'write-only' permissions setting"""
    archiver = request.getfixturevalue(archivers)

    # Create a repository first (need unrestricted permissions for that).
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "all")
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Create an initial archive to test with.
    create_test_files(archiver.input_path)
    cmd(archiver, "create", "archive1", "input")

    # Switch to write-only permissions.
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "write-only")

    # Try to create a new archive, which should succeed
    cmd(archiver, "create", "archive2", "input")

    # Try to list archives, which should fail (requires reading from data directory).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "repo-list")

    # Try to list files in an archive, which should fail (requires reading from data directory).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "list", "archive1")
    with pytest.raises(PermissionDenied):
        cmd(archiver, "list", "archive2")

    # Try to extract the archive, which should fail (data dir has "lw" permissions, no reading).
    with pytest.raises(PermissionDenied):
        with changedir("output"):
            cmd(archiver, "extract", "archive1")

    # Try to delete an archive, which should fail (requires reading from data directory to identify the archive).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "delete", "archive1")

    # Try to compact the repo, which should fail (data dir has "lw" permissions, no reading).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "compact")

    # Try to check the repo, which should fail (data dir has "lw" permissions, no reading).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "check")

    # Try to delete the repo, which should fail (no "D" permission on data dir).
    with pytest.raises(PermissionDenied):
        cmd(archiver, "repo-delete")

    # Switch to read-only permissions.
    monkeypatch.setenv("BORG_REPO_PERMISSIONS", "read-only")

    # Try to list archives, should work now.
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output

    # Try to list files in an archive, should work now.
    cmd(archiver, "list", "archive1")
    cmd(archiver, "list", "archive2")
