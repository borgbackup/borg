import os
import tempfile

from ...platform import acl_get, acl_set
from .platform_test import skipif_not_linux, skipif_fakeroot_detected, skipif_acls_not_working, skipif_no_ubel_user

# set module-level skips
pytestmark = [skipif_not_linux, skipif_fakeroot_detected]


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
def test_default_acl():
    tmpdir = tempfile.mkdtemp()
    assert get_acl(tmpdir) == {}
    set_acl(tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
    assert get_acl(tmpdir)["acl_access"] == ACCESS_ACL
    assert get_acl(tmpdir)["acl_default"] == DEFAULT_ACL


@skipif_acls_not_working
@skipif_no_ubel_user
def test_non_ascii_acl():
    # Testing non-ascii ACL processing to see whether our code is robust.
    # I have no idea whether non-ascii ACLs are allowed by the standard,
    # but in practice they seem to be out there and must not make our code explode.
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


def test_utils():
    from ...platform.linux import acl_use_local_uid_gid

    assert acl_use_local_uid_gid(b"user:nonexistent1234:rw-:1234") == b"user:1234:rw-"
    assert acl_use_local_uid_gid(b"group:nonexistent1234:rw-:1234") == b"group:1234:rw-"
    assert acl_use_local_uid_gid(b"user:root:rw-:0") == b"user:0:rw-"
    assert acl_use_local_uid_gid(b"group:root:rw-:0") == b"group:0:rw-"
