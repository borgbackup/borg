import os
import struct
import tempfile

import pytest

from ...platform import acl_get, acl_set
from ...platform.base import MountEntry
from .platform_test import skipif_not_linux, skipif_fakeroot_detected, skipif_acls_not_working, skipif_no_ubel_user

# set module-level skips
pytestmark = [skipif_not_linux]


ACCESS_ACL = """\
user::rw-
user:root:rw-:0
user:9999:r--:9999
group::r--
group:root:r--:0
group:9999:r--:9999
mask::rw-
other::r--\
""".encode(
    "ascii"
)

DEFAULT_ACL = """\
user::rw-
user:root:r--:0
user:8888:r--:8888
group::r--
group:root:r--:0
group:8888:r--:8888
mask::rw-
other::r--\
""".encode(
    "ascii"
)


def get_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_acl(path, access=None, default=None, numeric_ids=False):
    item = {"acl_access": access, "acl_default": default}
    acl_set(path, item, numeric_ids=numeric_ids)


@skipif_acls_not_working
@skipif_fakeroot_detected
def test_access_acl():
    file = tempfile.NamedTemporaryFile()
    assert get_acl(file.name) == {}

    set_acl(
        file.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n",
        numeric_ids=False,
    )
    assert b"user:root:rw-:0" in get_acl(file.name)["acl_access"]
    assert b"group:root:rw-:0" in get_acl(file.name)["acl_access"]
    assert b"user:0:rw-:0" in get_acl(file.name, numeric_ids=True)["acl_access"]

    file2 = tempfile.NamedTemporaryFile()
    set_acl(
        file2.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n",
        numeric_ids=True,
    )
    assert b"user:9999:rw-:9999" in get_acl(file2.name)["acl_access"]
    assert b"group:9999:rw-:9999" in get_acl(file2.name)["acl_access"]


@skipif_acls_not_working
@skipif_fakeroot_detected
def test_default_acl():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert get_acl(tmpdir) == {}
        set_acl(tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
        assert get_acl(tmpdir)["acl_access"] == ACCESS_ACL
        assert get_acl(tmpdir)["acl_default"] == DEFAULT_ACL


@skipif_acls_not_working
@skipif_no_ubel_user
@skipif_fakeroot_detected
def test_non_ascii_acl():
    # Testing non-ASCII ACL processing to see whether our code is robust.
    # I have no idea whether non-ASCII ACLs are allowed by the standard,
    # but in practice they seem to be out there and must not cause failures.
    file = tempfile.NamedTemporaryFile()
    assert get_acl(file.name) == {}
    nothing_special = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\n"
    # TODO: can this be tested without having an existing system user übel with uid 666 gid 666?
    user_entry = "user:übel:rw-:666".encode()
    user_entry_numeric = b"user:666:rw-:666"
    group_entry = "group:übel:rw-:666".encode()
    group_entry_numeric = b"group:666:rw-:666"
    acl = b"\n".join([nothing_special, user_entry, group_entry])
    set_acl(file.name, access=acl, numeric_ids=False)

    acl_access = get_acl(file.name, numeric_ids=False)["acl_access"]
    assert user_entry in acl_access
    assert group_entry in acl_access

    acl_access_numeric = get_acl(file.name, numeric_ids=True)["acl_access"]
    assert user_entry_numeric in acl_access_numeric
    assert group_entry_numeric in acl_access_numeric

    file2 = tempfile.NamedTemporaryFile()
    set_acl(file2.name, access=acl, numeric_ids=True)
    acl_access = get_acl(file2.name, numeric_ids=False)["acl_access"]
    assert user_entry in acl_access
    assert group_entry in acl_access

    acl_access_numeric = get_acl(file.name, numeric_ids=True)["acl_access"]
    assert user_entry_numeric in acl_access_numeric
    assert group_entry_numeric in acl_access_numeric


@skipif_fakeroot_detected
def test_acl_text_to_xattr():
    from ...platform.linux import acl_text_to_xattr

    acl = b"user::rw-\nuser:root:rw-:0\nuser:9999:r--:9999\ngroup::r--\ngroup:8888:rw-:8888\nmask::rw-\nother::r--"
    binary = acl_text_to_xattr(acl, numeric_ids=True)
    header, entries = binary[:4], binary[4:]
    assert header == (2).to_bytes(4, "little")  # POSIX_ACL_XATTR_VERSION
    parsed = [struct.unpack("<HHI", entries[i : i + 8]) for i in range(0, len(entries), 8)]
    assert parsed == [
        (0x01, 6, 0xFFFFFFFF),  # ACL_USER_OBJ  user::rw-
        (0x02, 6, 0),  # ACL_USER  user:root:rw-:0
        (0x02, 4, 9999),  # ACL_USER  user:9999:r--:9999
        (0x04, 4, 0xFFFFFFFF),  # ACL_GROUP_OBJ  group::r--
        (0x08, 6, 8888),  # ACL_GROUP  group:8888:rw-:8888
        (0x10, 6, 0xFFFFFFFF),  # ACL_MASK  mask::rw-
        (0x20, 4, 0xFFFFFFFF),  # ACL_OTHER  other::r--
    ]
    # unconvertible ACL text must raise ValueError:
    with pytest.raises(ValueError):
        acl_text_to_xattr(b"user:someuser:rw-")  # named entry without a stored numeric id
    with pytest.raises(ValueError):
        acl_text_to_xattr(b"flubber::rw-", numeric_ids=True)  # unknown entry type
    with pytest.raises(ValueError):
        acl_text_to_xattr(b"mask:0:rw-:0", numeric_ids=True)  # mask must not have a qualifier


@skipif_acls_not_working
@skipif_fakeroot_detected
def test_acl_text_to_xattr_matches_kernel():
    from ...platform.linux import acl_text_to_xattr

    file = tempfile.NamedTemporaryFile()
    access = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n"
    set_acl(file.name, access=access)
    kernel_binary = os.getxattr(file.name, "system.posix_acl_access")
    # borg stores the ACL as text - converting that back to the binary xattr
    # representation must give exactly what the kernel produced itself.
    item = get_acl(file.name)
    assert acl_text_to_xattr(item["acl_access"]) == kernel_binary
    item = get_acl(file.name, numeric_ids=True)
    assert acl_text_to_xattr(item["acl_access"], numeric_ids=True) == kernel_binary


@skipif_fakeroot_detected
def test_utils():
    from ...platform.linux import acl_use_local_uid_gid

    assert acl_use_local_uid_gid(b"user:nonexistent1234:rw-:1234") == b"user:1234:rw-"
    assert acl_use_local_uid_gid(b"group:nonexistent1234:rw-:1234") == b"group:1234:rw-"
    assert acl_use_local_uid_gid(b"user:root:rw-:0") == b"user:0:rw-"
    assert acl_use_local_uid_gid(b"group:root:rw-:0") == b"group:0:rw-"


@skipif_fakeroot_detected
def test_numeric_to_named_with_id_simple(monkeypatch):
    # Import here to ensure skip marker is applied before any platform-specific import side effects.
    from ...platform.linux import _acl_from_numeric_to_named_with_id

    # Pretend uid 1000 -> 'alice', gid 100 -> 'staff'
    from ...platform import platform_ug

    def _uid2user(uid, default=None):
        if uid == 1000:
            return "alice"
        return default

    def _gid2group(gid, default=None):
        if gid == 100:
            return "staff"
        return default

    monkeypatch.setattr(platform_ug, "_uid2user", _uid2user)
    monkeypatch.setattr(platform_ug, "_gid2group", _gid2group)

    src = b"\n".join([b"user::rwx", b"user:1000:r-x", b"group::r--", b"group:100:r--", b"mask::r-x", b"other::r--"])
    out = _acl_from_numeric_to_named_with_id(src)
    lines = set(out.split(b"\n"))
    assert b"user::rwx" in lines
    assert b"user:alice:r-x:1000" in lines
    assert b"group::r--" in lines
    assert b"group:staff:r--:100" in lines
    assert b"mask::r-x" in lines
    assert b"other::r--" in lines


@skipif_fakeroot_detected
def test_numeric_to_named_with_id_nonexistent_ids(monkeypatch):
    from ...platform.linux import _acl_from_numeric_to_named_with_id

    # Map functions return default (the given fallback), so names stay numeric but still append the fourth field
    from ...platform import platform_ug

    def _uid2user(uid, default=None):
        return default

    def _gid2group(gid, default=None):
        return default

    monkeypatch.setattr(platform_ug, "_uid2user", _uid2user)
    monkeypatch.setattr(platform_ug, "_gid2group", _gid2group)

    src = b"user:9999:r--\ngroup:8888:r--\n"
    out = _acl_from_numeric_to_named_with_id(src)
    lines = out.split(b"\n")
    assert lines[0] == b"user:9999:r--:9999"
    assert lines[1] == b"group:8888:r--:8888"


@skipif_fakeroot_detected
def test_numeric_to_numeric_with_id_simple():
    from ...platform.linux import _acl_from_numeric_to_numeric_with_id

    src = b"\n".join([b"user::rwx", b"user:1000:r-x", b"group::r--", b"group:100:r--", b"mask::r-x", b"other::r--"])
    out = _acl_from_numeric_to_numeric_with_id(src)
    lines = set(out.split(b"\n"))
    assert b"user::rwx" in lines
    assert b"user:1000:r-x:1000" in lines
    assert b"group::r--" in lines
    assert b"group:100:r--:100" in lines
    assert b"mask::r-x" in lines
    assert b"other::r--" in lines


# /proc/self/mountinfo lines captured on Debian 13 (the fuse lines while borg mount was running,
# with "subtype=borgfs" / without it / with "-o fsname=other"; the mountpoint has a space in it).
MOUNTINFO = b"""\
24 29 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:11 - proc proc rw
25 29 0:6 / /dev rw,nosuid,relatime shared:2 - devtmpfs udev rw,size=4045056k,nr_inodes=1011264,mode=755,inode64
29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
31 25 0:26 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw,size=4068456k,nr_inodes=1017114,inode64
67 42 0:48 / /tmp/m14/mnt\\040point ro,nosuid,nodev,relatime shared:150 - fuse.borgfs borgfs ro,user_id=0,group_id=0
68 42 0:49 / /tmp/m14/mnt2 ro,nosuid,nodev,relatime shared:151 - fuse borgfs ro,user_id=0,group_id=0
69 42 0:50 / /tmp/m14/mnt3 ro,nosuid,nodev,relatime shared:152 - fuse.borgfs other ro,user_id=0,group_id=0
"""


def test_parse_mountinfo():
    from ...platform.linux import parse_mountinfo

    assert parse_mountinfo(MOUNTINFO.splitlines()) == [
        MountEntry("proc", "proc", "/proc"),
        MountEntry("udev", "devtmpfs", "/dev"),
        MountEntry("/dev/sda1", "ext4", "/"),
        MountEntry("tmpfs", "tmpfs", "/dev/shm"),
        MountEntry("borgfs", "fuse.borgfs", "/tmp/m14/mnt point"),
        MountEntry("borgfs", "fuse", "/tmp/m14/mnt2"),
        MountEntry("other", "fuse.borgfs", "/tmp/m14/mnt3"),
    ]


def test_parse_mountinfo_escapes():
    from ...platform.linux import parse_mountinfo

    # space, tab, newline and backslash are escaped as octal byte values; non-ascii bytes are not escaped.
    line = b"1 2 0:3 / /mnt/a\\040b\\011c\\012d\\134e\\303\\244f\xc3\xb6 rw - ext4 /dev/x\\040y rw"
    assert parse_mountinfo([line]) == [MountEntry("/dev/x y", "ext4", "/mnt/a b\tc\nd\\eäfö")]


def test_parse_mountinfo_skips_garbage():
    from ...platform.linux import parse_mountinfo

    assert parse_mountinfo([b"", b"no separator here", b"1 2 - ext4 /dev/x rw"]) == []
