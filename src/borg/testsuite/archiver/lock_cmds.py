import os
import subprocess
import time

from ...constants import *  # NOQA
from . import cmd, generate_archiver_tests, RK_ENCRYPTION
from ...helpers import CommandError

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_break_lock(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "break-lock")


def test_with_lock(tmp_path):
    repo_path = tmp_path / "repo"
    env = os.environ.copy()
    env["BORG_REPO"] = "file://" + str(repo_path)
    command0 = "python3", "-m", "borg", "repo-create", "--encryption=none"
    # timings must be adjusted so that command1 keeps running while command2 tries to get the lock,
    # so that lock acquisition for command2 fails as the test expects it.
    lock_wait, execution_time, startup_wait = 2, 4, 1
    assert lock_wait < execution_time - startup_wait
    command1 = "python3", "-c", f'import time; print("first command - acquires the lock"); time.sleep({execution_time})'
    command2 = "python3", "-c", 'print("second command - should never get executed")'
    borgwl = "python3", "-m", "borg", "with-lock", f"--lock-wait={lock_wait}"
    popen_options = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    subprocess.run(command0, env=env, check=True, text=True, capture_output=True)
    assert repo_path.exists()
    with subprocess.Popen([*borgwl, *command1], **popen_options) as p1:
        time.sleep(startup_wait)  # wait until p1 is running
        # now try to get another lock on the same repository:
        with subprocess.Popen([*borgwl, *command2], **popen_options) as p2:
            out, err_out = p2.communicate()
            assert "second command" not in out  # command2 is "locked out"
            assert "Failed to create/acquire the lock" in err_out
            assert p2.returncode == 73  # LockTimeout: could not acquire the lock, p1 already has it
        out, err_out = p1.communicate()
        assert "first command" in out  # command1 was executed and had the lock
        assert not err_out
        assert p1.returncode == 0


def test_with_lock_non_existent_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    command = ["non_existent_command"]
    expected_ec = CommandError().exit_code
    cmd(archiver, "with-lock", *command, fork=True, exit_code=expected_ec)
