import functools
import os
import sys
import tempfile

import pytest

from ..platformflags import is_win32
from ..platform import acl_get, acl_set, swidth
from ..platform import get_process_id, process_alive
from . import unopened_tempfile
from .locking import free_pid  # NOQA


ACCESS_ACL = """
user::rw-
user:root:rw-:0
user:9999:r--:9999
group::r--
group:root:r--:0
group:9999:r--:9999
mask::rw-
other::r--
""".strip().encode(
    "ascii"
)

DEFAULT_ACL = """
user::rw-
user:root:r--:0
user:8888:r--:8888
group::r--
group:root:r--:0
group:8888:r--:8888
mask::rw-
other::r--
""".strip().encode(
    "ascii"
)

# _acls_working = None


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
            access = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n"
            acl = {"acl_access": access}
            acl_set(filepath, acl)
            read_acl = {}
            acl_get(filepath, read_acl, os.stat(filepath))
            read_acl_access = read_acl.get("acl_access", None)
            if read_acl_access and b"user::rw-" in read_acl_access:
                return True
        except PermissionError:
            pass
        return False


def get_linux_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_linux_acl(path, access=None, default=None, numeric_ids=False):
    item = {"acl_access": access, "acl_default": default}
    acl_set(path, item, numeric_ids=numeric_ids)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="linux only test")
@pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
@pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
def test_linux_access_acl():
    file = tempfile.NamedTemporaryFile()
    assert get_linux_acl(file.name) == {}

    set_linux_acl(
        file.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n",
        numeric_ids=False,
    )
    assert b"user:root:rw-:0" in get_linux_acl(file.name)["acl_access"]
    assert b"group:root:rw-:0" in get_linux_acl(file.name)["acl_access"]
    assert b"user:0:rw-:0" in get_linux_acl(file.name, numeric_ids=True)["acl_access"]

    file2 = tempfile.NamedTemporaryFile()
    set_linux_acl(
        file2.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n",
        numeric_ids=True,
    )
    assert b"user:9999:rw-:9999" in get_linux_acl(file2.name)["acl_access"]
    assert b"group:9999:rw-:9999" in get_linux_acl(file2.name)["acl_access"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="linux only test")
@pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
@pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
def test_linux_default_acl():
    tmpdir = tempfile.mkdtemp()
    assert get_linux_acl(tmpdir) == {}
    set_linux_acl(tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
    assert get_linux_acl(tmpdir)["acl_access"] == ACCESS_ACL
    assert get_linux_acl(tmpdir)["acl_default"] == DEFAULT_ACL


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="linux only test")
@pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
@pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
@pytest.mark.skipif(not user_exists("übel"), reason="requires übel user")
def test_linux_non_ascii_acl():
    # Testing non-ascii ACL processing to see whether our code is robust.
    # I have no idea whether non-ascii ACLs are allowed by the standard,
    # but in practice they seem to be out there and must not make our code explode.
    file = tempfile.NamedTemporaryFile()
    assert get_linux_acl(file.name) == {}
    nothing_special = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\n"
    # TODO: can this be tested without having an existing system user übel with uid 666 gid 666?
    user_entry = "user:übel:rw-:666".encode()
    user_entry_numeric = b"user:666:rw-:666"
    group_entry = "group:übel:rw-:666".encode()
    group_entry_numeric = b"group:666:rw-:666"
    acl = b"\n".join([nothing_special, user_entry, group_entry])
    set_linux_acl(file.name, access=acl, numeric_ids=False)

    acl_access = get_linux_acl(file.name, numeric_ids=False)["acl_access"]
    assert user_entry in acl_access
    assert group_entry in acl_access

    acl_access_numeric = get_linux_acl(file.name, numeric_ids=True)["acl_access"]
    assert user_entry_numeric in acl_access_numeric
    assert group_entry_numeric in acl_access_numeric

    file2 = tempfile.NamedTemporaryFile()
    set_linux_acl(file2.name, access=acl, numeric_ids=True)
    acl_access = get_linux_acl(file2.name, numeric_ids=False)["acl_access"]
    assert user_entry in acl_access
    assert group_entry in acl_access

    acl_access_numeric = get_linux_acl(file.name, numeric_ids=True)["acl_access"]
    assert user_entry_numeric in acl_access_numeric
    assert group_entry_numeric in acl_access_numeric


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="linux only test")
@pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
def test_linux_utils():
    from ..platform.linux import acl_use_local_uid_gid

    assert acl_use_local_uid_gid(b"user:nonexistent1234:rw-:1234") == b"user:1234:rw-"
    assert acl_use_local_uid_gid(b"group:nonexistent1234:rw-:1234") == b"group:1234:rw-"
    assert acl_use_local_uid_gid(b"user:root:rw-:0") == b"user:0:rw-"
    assert acl_use_local_uid_gid(b"group:root:rw-:0") == b"group:0:rw-"


def get_darwin_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_darwin_acl(path, acl, numeric_ids=False):
    item = {"acl_extended": acl}
    acl_set(path, item, numeric_ids=numeric_ids)


@pytest.mark.skipif(not sys.platform.startswith("darwin"), reason="macOS only test")
@pytest.mark.skipif(fakeroot_detected(), reason="not compatible with fakeroot")
@pytest.mark.skipif(not are_acls_working(), reason="ACLs do not work")
def test_darwin_access_acl(tmp_path):
    file = tempfile.NamedTemporaryFile()
    assert get_darwin_acl(file.name) == {}
    set_darwin_acl(
        file.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=False,
    )
    assert (
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014:staff:20:allow:read" in get_darwin_acl(file.name)["acl_extended"]
    )
    assert b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read" in get_darwin_acl(file.name)["acl_extended"]

    file2 = tempfile.NamedTemporaryFile()
    set_darwin_acl(
        file2.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=True,
    )
    assert (
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:wheel:0:allow:read" in get_darwin_acl(file2.name)["acl_extended"]
    )
    assert (
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000::0:allow:read"
        in get_darwin_acl(file2.name, numeric_ids=True)["acl_extended"]
    )


@pytest.mark.skipif(not sys.platform.startswith(("linux", "freebsd", "darwin")), reason="POSIX only tests")
def test_posix_swidth_ascii():
    assert swidth("borg") == 4


@pytest.mark.skipif(not sys.platform.startswith(("linux", "freebsd", "darwin")), reason="POSIX only tests")
def test_posix_swidth_cjk():
    assert swidth("バックアップ") == 6 * 2


@pytest.mark.skipif(not sys.platform.startswith(("linux", "freebsd", "darwin")), reason="POSIX only tests")
def test_posix_swidth_mixed():
    assert swidth("borgバックアップ") == 4 + 6 * 2


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
