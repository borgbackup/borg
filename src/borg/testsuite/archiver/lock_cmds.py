import os

from ...constants import *  # NOQA
from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_break_lock(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "break-lock")


def test_with_lock(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    lock_path = os.path.join(archiver.repository_path, "lock.exclusive")
    command = "python3", "-c", 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
    cmd(archiver, "with-lock", *command, fork=True, exit_code=42)


def test_with_lock_non_existent_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    command = ["non_existent_command"]
    cmd(archiver, "with-lock", *command, fork=True, exit_code=EXIT_ERROR)
