import os
import subprocess
import tempfile
import time

import pytest
import platformdirs

from . import exec_cmd
from ...platformflags import is_win32
from ...helpers import get_runtime_dir


def have_a_short_runtime_dir(mp):
    # under pytest, we use BORG_BASE_DIR to keep stuff away from the user's normal borg dirs.
    # this leads to a very long get_runtime_dir() path - too long for a socket file!
    # thus, we override that again via BORG_RUNTIME_DIR to get a shorter path.
    mp.setenv("BORG_RUNTIME_DIR", os.path.join(platformdirs.user_runtime_dir(), "pytest"))


@pytest.fixture
def serve_socket(monkeypatch):
    have_a_short_runtime_dir(monkeypatch)
    # use a random unique socket filename, so tests can run in parallel.
    socket_file = tempfile.mktemp(suffix=".sock", prefix="borg-", dir=get_runtime_dir())
    with subprocess.Popen(["borg", "serve", f"--socket={socket_file}"]) as p:
        while not os.path.exists(socket_file):
            time.sleep(0.01)  # wait until socket server has started
        yield socket_file
        p.terminate()


@pytest.mark.skipif(is_win32, reason="hangs on win32")
def test_with_socket(serve_socket, tmpdir, monkeypatch):
    have_a_short_runtime_dir(monkeypatch)
    repo_path = str(tmpdir.join("repo"))

    ret, output = exec_cmd(
        f"--socket={serve_socket}", f"--repo=socket://{repo_path}", "repo-create", "--encryption=none"
    )
    assert ret == 0

    ret, output = exec_cmd(f"--socket={serve_socket}", f"--repo=socket://{repo_path}", "repo-info")
    assert ret == 0
    assert "Repository ID: " in output

    monkeypatch.setenv("BORG_DELETE_I_KNOW_WHAT_I_AM_DOING", "YES")
    ret, output = exec_cmd(f"--socket={serve_socket}", f"--repo=socket://{repo_path}", "repo-delete")
    assert ret == 0


@pytest.mark.skipif(is_win32, reason="hangs on win32")
def test_socket_permissions(serve_socket):
    st = os.stat(serve_socket)
    assert st.st_mode & 0o0777 == 0o0770  # user and group are permitted to use the socket
