import tempfile

import pytest

from .platform_test import skipif_not_win32
from ...platform import SyncFile
from ...platform import windows

# Set module-level skips
pytestmark = [skipif_not_win32]


def test_syncfile_basic(tmp_path):
    """Integration: SyncFile creates file and writes data correctly."""
    path = tmp_path / "testfile"
    with SyncFile(path, binary=True) as sf:
        sf.write(b"hello borg")
    assert path.read_bytes() == b"hello borg"


def test_syncfile_file_exists_error(tmp_path):
    """SyncFile raises FileExistsError if file already exists."""
    path = tmp_path / "testfile"
    path.touch()
    with pytest.raises(FileExistsError):
        SyncFile(path, binary=True)


def test_syncfile_text_mode(tmp_path):
    """SyncFile works in text mode."""
    path = tmp_path / "testfile.txt"
    with SyncFile(path) as sf:
        sf.write("hello text")
    assert path.read_text() == "hello text"


def test_syncfile_fd_fallback(tmp_path):
    """SyncFile with fd falls back to base implementation (mirrors SaveFile usage)."""
    fd, fpath = tempfile.mkstemp(dir=tmp_path)
    with SyncFile(fpath, fd=fd, binary=True) as sf:
        sf.write(b"fallback test")
    with open(fpath, "rb") as f:
        assert f.read() == b"fallback test"


def test_syncfile_sync(tmp_path):
    """Explicit sync() does not raise."""
    path = tmp_path / "testfile"
    with SyncFile(path, binary=True) as sf:
        sf.write(b"sync test data")
        sf.sync()


def test_syncfile_uses_write_through(tmp_path, monkeypatch):
    """Verify CreateFileW is called with FILE_FLAG_WRITE_THROUGH."""
    calls = []
    original = windows._CreateFileW

    def mock_create(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(windows, "_CreateFileW", mock_create)

    path = tmp_path / "testfile"
    with windows.SyncFile(path, binary=True) as sf:
        sf.write(b"write-through test")

    assert len(calls) == 1
    flags_attrs = calls[0][5]  # 6th arg: dwFlagsAndAttributes
    assert flags_attrs & windows.FILE_FLAG_WRITE_THROUGH
