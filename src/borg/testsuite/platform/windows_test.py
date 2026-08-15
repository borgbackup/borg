import os
import tempfile

import pytest

from .platform_test import skipif_not_win32
from .. import are_symlinks_supported
from ...platform import SyncFile, set_times

# Set module-level skips
pytestmark = [skipif_not_win32]

# timestamps used by the set_times tests. a FILETIME has a resolution of 100ns,
# so only use values that are a multiple of 100ns to be able to compare exactly.
ATIME_NS, MTIME_NS, BIRTHTIME_NS = 1500000000000000100, 1400000000000000200, 1300000000000000300


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
    from borg.platform import windows

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


def assert_times(st, *, atime_ns=ATIME_NS, mtime_ns=MTIME_NS, birthtime_ns=BIRTHTIME_NS):
    assert st.st_atime_ns == atime_ns
    assert st.st_mtime_ns == mtime_ns
    if hasattr(st, "st_birthtime_ns"):  # Python >= 3.12 on Windows
        assert st.st_birthtime_ns == birthtime_ns


def test_set_times_file(tmp_path):
    """set_times sets atime, mtime and birthtime of a file given by path."""
    path = tmp_path / "file"
    path.write_bytes(b"data")
    set_times(str(path), atime_ns=ATIME_NS, mtime_ns=MTIME_NS, birthtime_ns=BIRTHTIME_NS)
    assert_times(os.stat(path))


def test_set_times_fd(tmp_path):
    """set_times works on an open file descriptor, like borg extract uses it."""
    path = tmp_path / "file"
    with open(path, "wb") as f:
        f.write(b"data")
        f.flush()
        set_times(str(path), atime_ns=ATIME_NS, mtime_ns=MTIME_NS, birthtime_ns=BIRTHTIME_NS, fd=f.fileno())
    # the timestamps must survive closing the file we have written to.
    assert_times(os.stat(path))


def test_set_times_directory(tmp_path):
    """set_times works on a directory (needs FILE_FLAG_BACKUP_SEMANTICS)."""
    path = tmp_path / "dir"
    path.mkdir()
    set_times(str(path), atime_ns=ATIME_NS, mtime_ns=MTIME_NS, birthtime_ns=BIRTHTIME_NS)
    assert_times(os.stat(path))


def test_set_times_without_birthtime(tmp_path):
    """set_times leaves the birthtime alone if we do not give one."""
    path = tmp_path / "file"
    path.write_bytes(b"data")
    birthtime_ns = getattr(os.stat(path), "st_birthtime_ns", None)
    set_times(str(path), atime_ns=ATIME_NS, mtime_ns=MTIME_NS)
    assert_times(os.stat(path), birthtime_ns=birthtime_ns)


@pytest.mark.skipif(not are_symlinks_supported(), reason="symlinks not supported")
def test_set_times_symlink_not_followed(tmp_path):
    """set_times(follow_symlinks=False) works on the symlink itself, not on its target."""
    target = tmp_path / "target"
    target.write_bytes(b"data")
    target_times = os.stat(target)
    link = tmp_path / "link"
    os.symlink(str(target), str(link))
    set_times(str(link), atime_ns=ATIME_NS, mtime_ns=MTIME_NS, birthtime_ns=BIRTHTIME_NS, follow_symlinks=False)
    assert_times(os.stat(link, follow_symlinks=False))
    st_target = os.stat(target)
    assert st_target.st_mtime_ns == target_times.st_mtime_ns
    assert st_target.st_atime_ns == target_times.st_atime_ns


def test_set_times_nonexistent(tmp_path):
    """set_times raises OSError if there is no such file."""
    with pytest.raises(OSError):
        set_times(str(tmp_path / "nonexistent"), atime_ns=ATIME_NS, mtime_ns=MTIME_NS)
