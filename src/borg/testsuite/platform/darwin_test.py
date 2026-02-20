import os
import tempfile

from ...platform import acl_get, acl_set
from ...platform import fdatasync, sync_dir
from .platform_test import skipif_not_darwin, skipif_fakeroot_detected, skipif_acls_not_working

# Set module-level skips
pytestmark = [skipif_not_darwin, skipif_fakeroot_detected]


def get_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_acl(path, acl, numeric_ids=False):
    item = {"acl_extended": acl}
    acl_set(path, item, numeric_ids=numeric_ids)


@skipif_acls_not_working
def test_extended_acl():
    file = tempfile.NamedTemporaryFile()
    assert get_acl(file.name) == {}
    set_acl(
        file.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=False,
    )
    assert b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014:staff:20:allow:read" in get_acl(file.name)["acl_extended"]
    assert b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read" in get_acl(file.name)["acl_extended"]

    file2 = tempfile.NamedTemporaryFile()
    set_acl(
        file2.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=True,
    )
    assert b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:wheel:0:allow:read" in get_acl(file2.name)["acl_extended"]
    assert (
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000::0:allow:read"
        in get_acl(file2.name, numeric_ids=True)["acl_extended"]
    )


def test_fdatasync_uses_f_fullfsync(monkeypatch):
    """Verify fcntl F_FULLFSYNC is called."""
    import fcntl as fcntl_mod
    from ...platform import darwin

    calls = []
    original_fcntl = fcntl_mod.fcntl

    def mock_fcntl(fd, cmd, *args):
        calls.append((fd, cmd))
        return original_fcntl(fd, cmd, *args)

    monkeypatch.setattr(fcntl_mod, "fcntl", mock_fcntl)

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"test data")
        tmp.flush()
        darwin.fdatasync(tmp.fileno())

    assert any(cmd == fcntl_mod.F_FULLFSYNC for _, cmd in calls), "fdatasync should call fcntl with F_FULLFSYNC"


def test_fdatasync_falls_back_to_fsync(monkeypatch):
    """Verify os.fsync fallback when F_FULLFSYNC fails."""
    import fcntl as fcntl_mod
    from ...platform import darwin

    fsync_calls = []

    def mock_fcntl(fd, cmd, *args):
        if cmd == fcntl_mod.F_FULLFSYNC:
            raise OSError("F_FULLFSYNC not supported")
        return 0

    def mock_fsync(fd):
        fsync_calls.append(fd)

    monkeypatch.setattr(fcntl_mod, "fcntl", mock_fcntl)
    monkeypatch.setattr(os, "fsync", mock_fsync)

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"test data")
        tmp.flush()
        darwin.fdatasync(tmp.fileno())

    assert len(fsync_calls) == 1, "Should fall back to os.fsync when F_FULLFSYNC fails"


def test_fdatasync_basic():
    """Integration: fdatasync completes on a real file without error."""
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(b"test data for fdatasync")
        tmp.flush()
        fdatasync(tmp.fileno())


def test_sync_dir_basic():
    """Integration: sync_dir completes on a real directory without error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sync_dir(tmpdir)
