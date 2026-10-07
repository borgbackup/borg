import io
import os

import pytest

from ...platform import swidth, SyncFile, on_different_mounts
from ...platformflags import is_win32


def test_swidth_ascii():
    assert swidth("borg") == 4


def test_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


def test_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2


def test_syncfile_seek_tell(tmp_path):
    """SyncFile exposes seek() and tell() from the underlying file object."""
    path = tmp_path / "testfile"
    with SyncFile(path, binary=True) as sf:
        sf.write(b"hello world")
        assert sf.tell() == 11
        sf.seek(0, io.SEEK_SET)
        assert sf.tell() == 0
        sf.seek(0, io.SEEK_END)
        assert sf.tell() == 11
        sf.seek(5, io.SEEK_SET)
        assert sf.tell() == 5
        assert sf.read() == b" world"
    assert path.read_bytes() == b"hello world"


def test_syncfile_close_idempotent(tmp_path):
    """Calling SyncFile.close() twice does not raise."""
    path = tmp_path / "testfile"
    sf = SyncFile(path, binary=True)
    sf.write(b"data")
    sf.close()
    sf.close()  # must not raise


@pytest.mark.skipif(is_win32, reason="can not open directories on windows")
def test_on_different_mounts(tmp_path):
    (tmp_path / "subdir").mkdir()
    # a directory that is usually a separately mounted filesystem (devtmpfs, devfs, procfs, tmpfs, ...):
    candidates = [p for p in ("/dev", "/proc", "/tmp") if os.path.isdir(p)]
    other_mount = next((p for p in candidates if os.stat(p).st_dev != os.stat("/").st_dev), None)
    fds = {}
    try:
        for path in "/", other_mount, tmp_path, tmp_path / "subdir":
            if path is not None:
                fds[path] = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        assert on_different_mounts(fds[tmp_path], fds[tmp_path / "subdir"]) is False
        assert on_different_mounts(fds[tmp_path], fds[tmp_path]) is False
        if other_mount is None:
            pytest.skip("found no separately mounted filesystem")
        assert on_different_mounts(fds["/"], fds[other_mount]) is True
    finally:
        for fd in fds.values():
            os.close(fd)
