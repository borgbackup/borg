import os
import tempfile

from ...platform import acl_get, acl_set
from .platform_test import skipif_not_freebsd, skipif_fakeroot_detected, skipif_acls_not_working

# set module-level skips
pytestmark = [skipif_not_freebsd, skipif_fakeroot_detected]


ACCESS_ACL = """\
user::rw-
user:root:rw-
user:9999:r--
group::r--
group:wheel:r--
group:9999:r--
mask::rw-
other::r--
""".encode(
    "ascii"
)

DEFAULT_ACL = """\
user::rw-
user:root:r--
user:8888:r--
group::r--
group:wheel:r--
group:8888:r--
mask::rw-
other::r--
""".encode(
    "ascii"
)


def get_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_acl(path, access=None, default=None, nfs4=None, numeric_ids=False):
    item = {"acl_access": access, "acl_default": default, "acl_nfs4": nfs4}
    acl_set(path, item, numeric_ids=numeric_ids)


@skipif_acls_not_working
def test_access_acl():
    file1 = tempfile.NamedTemporaryFile()
    assert get_acl(file1.name) == {}
    set_acl(
        file1.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-\ngroup:wheel:rw-\n",
        numeric_ids=False,
    )
    acl_access_names = get_acl(file1.name, numeric_ids=False)["acl_access"]
    assert b"user:root:rw-" in acl_access_names
    assert b"group:wheel:rw-" in acl_access_names
    acl_access_ids = get_acl(file1.name, numeric_ids=True)["acl_access"]
    assert b"user:0:rw-" in acl_access_ids
    assert b"group:0:rw-" in acl_access_ids

    file2 = tempfile.NamedTemporaryFile()
    set_acl(
        file2.name, access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:0:rw-\ngroup:0:rw-\n", numeric_ids=True
    )
    acl_access_names = get_acl(file2.name, numeric_ids=False)["acl_access"]
    assert b"user:root:rw-" in acl_access_names
    assert b"group:wheel:rw-" in acl_access_names
    acl_access_ids = get_acl(file2.name, numeric_ids=True)["acl_access"]
    assert b"user:0:rw-" in acl_access_ids
    assert b"group:0:rw-" in acl_access_ids

    file3 = tempfile.NamedTemporaryFile()
    set_acl(
        file3.name,
        access=b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:wheel:rw-:9999\n",
        numeric_ids=True,
    )
    acl_access_ids = get_acl(file3.name, numeric_ids=True)["acl_access"]
    assert b"user:9999:rw-" in acl_access_ids
    assert b"group:9999:rw-" in acl_access_ids


@skipif_acls_not_working
def test_default_acl():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert get_acl(tmpdir) == {}
        set_acl(tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
        assert get_acl(tmpdir)["acl_access"] == ACCESS_ACL
        assert get_acl(tmpdir)["acl_default"] == DEFAULT_ACL


@skipif_acls_not_working
def test_default_acl_only():
    # a directory can have a default ACL while its access ACL is just the traditional permission
    # bits. acl_extended_link_np() only considers the access ACL, so borg must not rely on it
    # alone for directories - otherwise the default ACL would not be archived at all.
    with tempfile.TemporaryDirectory() as tmpdir:
        set_acl(tmpdir, default=DEFAULT_ACL)
        item = get_acl(tmpdir)
        assert "acl_access" not in item
        assert item["acl_default"] == DEFAULT_ACL


@skipif_acls_not_working
def test_access_acl_only_no_empty_default():
    # a directory without a default ACL must not get an empty acl_default archived.
    with tempfile.TemporaryDirectory() as tmpdir:
        set_acl(tmpdir, access=ACCESS_ACL)
        item = get_acl(tmpdir)
        assert item["acl_access"] == ACCESS_ACL
        assert "acl_default" not in item


# nfs4 acls testing not implemented.
