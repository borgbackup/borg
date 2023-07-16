import os

from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION
from . import pytest_generate_tests  # NOQA


def test_break_lock(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "break-lock")


def test_with_lock(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    lock_path = os.path.join(repo_path, "lock.exclusive")
    command = "python3", "-c", 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
    cmd(archiver, f"--repo={repo_location}", "with-lock", *command, fork=True, exit_code=42)
