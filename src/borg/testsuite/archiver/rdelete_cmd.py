import os

from ...constants import *  # NOQA
from . import create_regular_file, cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_delete_repo(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir2/file2", size=1024 * 80)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "create", "test.2", "input")
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "no"
    cmd(archiver, "rdelete", exit_code=2)
    assert os.path.exists(archiver.repository_path)
    os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
    cmd(archiver, "rdelete")
    # Make sure the repo is gone
    assert not os.path.exists(archiver.repository_path)
