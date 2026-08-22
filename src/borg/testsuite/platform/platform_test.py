import errno
import functools
import os
import stat

import pytest

from ...platformflags import is_darwin, is_freebsd, is_linux, is_win32
from ...platform import acl_get, acl_set
from ...platform import get_process_id, process_alive
from ...platform import base
from .. import unopened_tempfile
from ..fslocking_test import free_pid  # NOQA


def fakeroot_detected():
    return "FAKEROOTKEY" in os.environ


def user_exists(username):
    if not is_win32:
        import pwd

        try:
            pwd.getpwnam(username)
            return True
        except (KeyError, ValueError):
            pass
    return False


@functools.lru_cache
def are_acls_working():
    with unopened_tempfile() as filepath:
        open(filepath, "w").close()
        try:
            if is_darwin:
                acl_key = "acl_extended"
                acl_value = b"!#acl 1\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n"
            elif is_linux:
                acl_key = "acl_access"
                acl_value = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n"
            elif is_freebsd:
                acl_key = "acl_access"
                acl_value = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-\ngroup:wheel:rw-\n"
            else:
                return False  # ACLs unsupported on this platform.
            write_acl = {acl_key: acl_value}
            acl_set(filepath, write_acl)
            read_acl = {}
            acl_get(filepath, read_acl, os.stat(filepath))
            acl = read_acl.get(acl_key, None)
            if acl is not None:
                if is_darwin:
                    check_for = b"root:0:allow:read"
                elif is_linux:
                    check_for = b"user::rw-"
                elif is_freebsd:
                    check_for = b"user::rw-"
                else:
                    return False  # ACLs unsupported on this platform.
                if check_for in acl:
                    return True
        except PermissionError:
            pass
        except OSError as e:
            if e.errno not in (errno.ENOTSUP,):
                raise
        return False


# define skips available to platform tests
skipif_not_linux = pytest.mark.skipif(not is_linux, reason="Linux-only test")
skipif_not_darwin = pytest.mark.skipif(not is_darwin, reason="Darwin-only test")
skipif_not_freebsd = pytest.mark.skipif(not is_freebsd, reason="FreeBSD-only test")
skipif_not_posix = pytest.mark.skipif(not (is_linux or is_freebsd or is_darwin), reason="POSIX-only tests")
skipif_fakeroot_detected = pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
skipif_acls_not_working = pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
skipif_not_win32 = pytest.mark.skipif(not is_win32, reason="Windows-only test")
skipif_no_ubel_user = pytest.mark.skipif(not user_exists("übel"), reason="requires übel user")


def test_process_alive(free_pid):  # NOQA
    id = get_process_id()
    assert process_alive(*id)
    host, pid, tid = id
    assert process_alive(host + "abc", pid, tid)
    assert process_alive(host, pid, tid + 1)
    assert not process_alive(host, free_pid, tid)


def test_process_id():
    hostname, pid, tid = get_process_id()
    assert isinstance(hostname, str)
    assert isinstance(pid, int)
    assert isinstance(tid, int)
    assert len(hostname) > 0
    assert pid > 0
    assert get_process_id() == (hostname, pid, tid)


# base.set_flags tests: fake lstat/lchflags, so they run on all platforms (incl. those without chflags).
FLAGS_TESTFILE = "base-set-flags-testfile"


def patch_flags(monkeypatch, current_flags, lchflags_func):
    class FakeStat:
        st_flags = current_flags

    real_lstat = os.lstat

    def fake_lstat(path, *args, **kwargs):
        return FakeStat() if path == FLAGS_TESTFILE else real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "lchflags", lchflags_func, raising=False)


def test_base_set_flags_masks_and_preserves(monkeypatch):
    # only settable flags may be influenced; all other bits must be preserved as-is, see #9039.
    calls = []
    patch_flags(monkeypatch, stat.SF_SNAPSHOT | stat.UF_COMPRESSED | stat.UF_NODUMP, lambda p, f: calls.append(f))
    base.set_flags(FLAGS_TESTFILE, stat.UF_IMMUTABLE | stat.UF_COMPRESSED)
    # UF_IMMUTABLE (settable) gets applied, UF_NODUMP (settable, not archived) gets cleared,
    # UF_COMPRESSED / SF_SNAPSHOT (not settable) keep their on-disk state, the archived value is ignored.
    assert calls == [stat.SF_SNAPSHOT | stat.UF_COMPRESSED | stat.UF_IMMUTABLE]


def test_base_set_flags_eperm_retries_without_sf_flags(monkeypatch):
    # when we lack permission for super-user-only flags, the owner-settable flags shall still be restored.
    calls = []

    def fake_lchflags(path, flags):
        calls.append(flags)
        if len(calls) == 1:
            raise OSError(errno.EPERM, "Operation not permitted", path)

    patch_flags(monkeypatch, stat.SF_SNAPSHOT, fake_lchflags)
    base.set_flags(FLAGS_TESTFILE, stat.UF_NODUMP | stat.SF_ARCHIVED)
    assert calls == [
        stat.SF_SNAPSHOT | stat.UF_NODUMP | stat.SF_ARCHIVED,  # full attempt
        stat.SF_SNAPSHOT | stat.UF_NODUMP,  # retry without super-user-only flags
    ]


def test_base_set_flags_eperm_raises_after_retry(monkeypatch):
    calls = []

    def fake_lchflags(path, flags):
        calls.append(flags)
        raise OSError(errno.EPERM, "Operation not permitted", path)

    patch_flags(monkeypatch, 0, fake_lchflags)
    with pytest.raises(OSError):
        base.set_flags(FLAGS_TESTFILE, stat.UF_NODUMP)
    assert len(calls) == 2  # full attempt + owner-settable-only retry


def test_base_set_flags_unsupported_fs(monkeypatch):
    def fake_lchflags(path, flags):
        raise OSError(errno.EOPNOTSUPP, "Operation not supported", path)

    patch_flags(monkeypatch, 0, fake_lchflags)
    base.set_flags(FLAGS_TESTFILE, stat.UF_NODUMP)  # must not raise


def test_base_set_flags_no_current_flags(monkeypatch):
    # if the current flags can't be determined, do nothing (rather than risk corrupting them).
    calls = []

    def fake_lstat(path, *args, **kwargs):
        raise OSError(errno.ENOENT, "No such file or directory", path)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    monkeypatch.setattr(os, "lchflags", lambda p, f: calls.append(f), raising=False)
    base.set_flags(FLAGS_TESTFILE, stat.UF_NODUMP)
    assert calls == []
