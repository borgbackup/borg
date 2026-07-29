"""Tests for the FUSE filesystem implementations that do not need an actual mount.

The ACL xattrs (see ACL_XATTRS) are emulated by the FUSE implementations, so we can
test them by directly calling the relevant methods with a fake item. Unlike the tests
in archiver/mount_cmds_test.py, this also works in environments where the kernel does
not offer ACL xattrs on FUSE mounts (e.g. mounts made inside a user namespace).
"""

import errno

import pytest

from ..helpers import StableDict
from ..item import Item
from ..platform import acl_text_to_xattr
from . import has_llfuse, has_pyfuse3, has_mfusepy, ENOATTR
from .platform.platform_test import skipif_not_linux

# the ACL xattrs are only emulated on Linux:
pytestmark = skipif_not_linux

skipif_no_llfuse_api = pytest.mark.skipif(not (has_llfuse or has_pyfuse3), reason="llfuse/pyfuse3 not available")
skipif_no_mfusepy = pytest.mark.skipif(not has_mfusepy, reason="mfusepy not available")

ACCESS_ACL = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:0\ngroup:root:rw-:0\n"
DEFAULT_ACL = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:r--:0\ngroup:root:r--:0\n"
BROKEN_ACL = b"flubber::rw-\n"  # can not be converted to the binary xattr representation


def make_item(*, acls=True, acl_access=ACCESS_ACL):
    item = Item(path="file", mode=0o100666, mtime=0, xattrs=StableDict({b"user.foo": b"bar"}))
    if acls:
        item.acl_access = acl_access
        item.acl_default = DEFAULT_ACL
    return item


def unwrap(method):
    """Get the undecorated method: with pyfuse3, the FUSE operations are async wrapped."""
    return getattr(method, "__wrapped__", method)


def llfuse_ops(item, numeric_ids=False):
    """Minimal stand-in for FuseOperations, providing what listxattr/getxattr need."""
    from ..fuse import FuseOperations

    class Operations:
        pass

    ops = Operations()
    ops.numeric_ids = numeric_ids
    ops.get_item = lambda inode: item
    return ops, unwrap(FuseOperations.listxattr), unwrap(FuseOperations.getxattr)


def mfusepy_ops(item, numeric_ids=False):
    """Minimal stand-in for borgfs, providing what listxattr/getxattr need."""
    from ..hlfuse import borgfs

    class Node:
        ino = 1

    class Operations:
        pass

    ops = Operations()
    ops.numeric_ids = numeric_ids
    ops._find_node = lambda path: Node()
    ops.get_inode = lambda ino: item
    return ops, borgfs.listxattr, borgfs.getxattr


@skipif_no_llfuse_api
def test_llfuse_listxattr_acls():
    ops, listxattr, _ = llfuse_ops(make_item())
    assert sorted(listxattr(ops, 1)) == [b"system.posix_acl_access", b"system.posix_acl_default", b"user.foo"]


@skipif_no_llfuse_api
def test_llfuse_listxattr_no_acls():
    ops, listxattr, _ = llfuse_ops(make_item(acls=False))
    assert list(listxattr(ops, 1)) == [b"user.foo"]


@skipif_no_llfuse_api
@pytest.mark.parametrize("numeric_ids", [False, True])
def test_llfuse_getxattr_acls(numeric_ids):
    ops, _, getxattr = llfuse_ops(make_item(), numeric_ids=numeric_ids)
    assert getxattr(ops, 1, b"system.posix_acl_access") == acl_text_to_xattr(ACCESS_ACL, numeric_ids=numeric_ids)
    assert getxattr(ops, 1, b"system.posix_acl_default") == acl_text_to_xattr(DEFAULT_ACL, numeric_ids=numeric_ids)
    assert getxattr(ops, 1, b"user.foo") == b"bar"  # "normal" xattrs still work


@skipif_no_llfuse_api
def test_llfuse_getxattr_acl_missing():
    from ..fuse_impl import llfuse

    ops, _, getxattr = llfuse_ops(make_item(acls=False))
    with pytest.raises(llfuse.FUSEError) as excinfo:
        getxattr(ops, 1, b"system.posix_acl_access")
    assert excinfo.value.errno == ENOATTR


@skipif_no_llfuse_api
def test_llfuse_getxattr_acl_broken():
    from ..fuse_impl import llfuse

    ops, _, getxattr = llfuse_ops(make_item(acl_access=BROKEN_ACL))
    with pytest.raises(llfuse.FUSEError) as excinfo:
        getxattr(ops, 1, b"system.posix_acl_access")
    assert excinfo.value.errno == errno.EIO


@skipif_no_mfusepy
def test_mfusepy_listxattr_acls():
    ops, listxattr, _ = mfusepy_ops(make_item())
    assert sorted(listxattr(ops, "/file")) == ["system.posix_acl_access", "system.posix_acl_default", "user.foo"]


@skipif_no_mfusepy
def test_mfusepy_listxattr_no_acls():
    ops, listxattr, _ = mfusepy_ops(make_item(acls=False))
    assert list(listxattr(ops, "/file")) == ["user.foo"]


@skipif_no_mfusepy
@pytest.mark.parametrize("numeric_ids", [False, True])
def test_mfusepy_getxattr_acls(numeric_ids):
    ops, _, getxattr = mfusepy_ops(make_item(), numeric_ids=numeric_ids)
    access = getxattr(ops, "/file", "system.posix_acl_access")
    assert access == acl_text_to_xattr(ACCESS_ACL, numeric_ids=numeric_ids)
    default = getxattr(ops, "/file", "system.posix_acl_default")
    assert default == acl_text_to_xattr(DEFAULT_ACL, numeric_ids=numeric_ids)
    assert getxattr(ops, "/file", "user.foo") == b"bar"  # "normal" xattrs still work


@skipif_no_mfusepy
def test_mfusepy_getxattr_acl_missing():
    from ..fuse_impl import hlfuse

    ops, _, getxattr = mfusepy_ops(make_item(acls=False))
    with pytest.raises(hlfuse.FuseOSError) as excinfo:
        getxattr(ops, "/file", "system.posix_acl_default")
    assert excinfo.value.errno == ENOATTR


@skipif_no_mfusepy
def test_mfusepy_getxattr_acl_broken():
    from ..fuse_impl import hlfuse

    ops, _, getxattr = mfusepy_ops(make_item(acl_access=BROKEN_ACL))
    with pytest.raises(hlfuse.FuseOSError) as excinfo:
        getxattr(ops, "/file", "system.posix_acl_access")
    assert excinfo.value.errno == errno.EIO
