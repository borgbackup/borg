import functools
import os

import pytest

from ..platformflags import is_darwin, is_freebsd, is_linux, is_win32
from ..platform import acl_get, acl_set
from ..platform import get_process_id, process_alive
from . import unopened_tempfile
from .locking import free_pid  # NOQA


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
            if is_freebsd:
                access = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-\n"
                contained = b"user:root:rw-"
            elif is_linux:
                access = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:0\n"
                contained = b"user:root:rw-:0"
            elif is_darwin:
                return True  # improve?
            else:
                return False  # unsupported platform
            acl = {"acl_access": access}
            acl_set(filepath, acl)
            read_acl = {}
            acl_get(filepath, read_acl, os.stat(filepath))
            read_acl_access = read_acl.get("acl_access", None)
            if read_acl_access and contained in read_acl_access:
                return True
        except PermissionError:
            pass
        return False


# define skips available to platform tests
skipif_not_linux = pytest.mark.skipif(not is_linux, reason="linux only test")
skipif_not_darwin = pytest.mark.skipif(not is_darwin, reason="darwin only test")
skipif_not_freebsd = pytest.mark.skipif(not is_freebsd, reason="freebsd only test")
skipif_not_posix = pytest.mark.skipif(not (is_linux or is_freebsd or is_darwin), reason="POSIX only tests")
skipif_fakeroot_detected = pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
skipif_acls_not_working = pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
skipif_no_ubel_user = pytest.mark.skipif(not user_exists("übel"), reason="requires übel user")


def test_process_alive(free_pid):
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
