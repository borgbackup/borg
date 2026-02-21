import os
import tempfile

import pytest

from .platform_test import skipif_not_win32

# Set module-level skips
pytestmark = [skipif_not_win32]


def test_syncfile_basic():
    """Integration: SyncFile creates file and writes data correctly."""
    from ...platform.windows import SyncFile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        with SyncFile(path, binary=True) as sf:
            sf.write(b"hello borg")
        with open(path, "rb") as f:
            assert f.read() == b"hello borg"


def test_syncfile_file_exists_error():
    """SyncFile raises FileExistsError if file already exists."""
    from ...platform.windows import SyncFile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        open(path, "w").close()
        with pytest.raises(FileExistsError):
            SyncFile(path, binary=True)


def test_syncfile_text_mode():
    """SyncFile works in text mode."""
    from ...platform.windows import SyncFile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile.txt")
        with SyncFile(path) as sf:
            sf.write("hello text")
        with open(path, "r") as f:
            assert f.read() == "hello text"


def test_syncfile_fd_fallback():
    """SyncFile with fd falls back to base implementation (mirrors SaveFile usage)."""
    from ...platform.windows import SyncFile

    with tempfile.TemporaryDirectory() as tmpdir:
        fd, path = tempfile.mkstemp(dir=tmpdir)
        with SyncFile(path, fd=fd, binary=True) as sf:
            sf.write(b"fallback test")
        with open(path, "rb") as f:
            assert f.read() == b"fallback test"


def test_syncfile_sync():
    """Explicit sync() does not raise."""
    from ...platform.windows import SyncFile

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        with SyncFile(path, binary=True) as sf:
            sf.write(b"sync test data")
            sf.sync()


def test_syncfile_uses_write_through(monkeypatch):
    """Verify CreateFileW is called with FILE_FLAG_WRITE_THROUGH."""
    from ...platform import windows

    calls = []
    original = windows._CreateFileW

    def mock_create(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(windows, "_CreateFileW", mock_create)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "testfile")
        with windows.SyncFile(path, binary=True) as sf:
            sf.write(b"write-through test")

    assert len(calls) == 1
    flags_attrs = calls[0][5]  # 6th arg: dwFlagsAndAttributes
    assert flags_attrs & windows.FILE_FLAG_WRITE_THROUGH
