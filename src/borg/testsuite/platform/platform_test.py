import errno
import functools
import os

import pytest

from ...platformflags import is_darwin, is_freebsd, is_linux, is_win32
from ...platform import acl_get, acl_set
from ...platform import get_process_id, process_alive
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
skipif_not_linux = pytest.mark.skipif(not is_linux, reason="linux only test")
skipif_not_darwin = pytest.mark.skipif(not is_darwin, reason="darwin only test")
skipif_not_freebsd = pytest.mark.skipif(not is_freebsd, reason="freebsd only test")
skipif_not_posix = pytest.mark.skipif(not (is_linux or is_freebsd or is_darwin), reason="POSIX only tests")
skipif_fakeroot_detected = pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
skipif_acls_not_working = pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
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
