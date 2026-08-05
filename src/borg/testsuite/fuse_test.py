"""Tests for the FUSE adapters that do not need an actual mount.

The archive VFS (see vfs_test.py) reports a missing xattr as a KeyError and an ACL it
can not convert as a ValueError - both FUSE adapters have to turn these into the right
errno, which is what we check here without mounting anything.
"""

import errno

import pytest

from . import has_llfuse, has_pyfuse3, has_mfusepy, ENOATTR

skipif_no_llfuse_api = pytest.mark.skipif(not (has_llfuse or has_pyfuse3), reason="llfuse/pyfuse3 not available")
skipif_no_mfusepy = pytest.mark.skipif(not has_mfusepy, reason="mfusepy not available")

XATTRS = [b"user.foo", b"system.posix_acl_access"]


class FakeVFS:
    """Minimal stand-in for the archive VFS: answers the xattr calls, however we want."""

    def __init__(self, exception=None):
        self.exception = exception

    def listxattr(self, ino):
        return list(XATTRS)

    def getxattr(self, ino, name):
        if self.exception is not None:
            raise self.exception
        return b"bar"


def unwrap(method):
    """Get the undecorated method: with pyfuse3, the FUSE operations are async wrapped."""
    return getattr(method, "__wrapped__", method)


def llfuse_ops(exception=None):
    from ..fuse import FuseOperations

    class Operations:
        pass

    ops = Operations()
    ops.vfs = FakeVFS(exception)
    return ops, unwrap(FuseOperations.listxattr), unwrap(FuseOperations.getxattr)


def mfusepy_ops(exception=None):
    from ..hlfuse import borgfs

    class Node:
        ino = 1

    class Operations:
        pass

    ops = Operations()
    ops.vfs = FakeVFS(exception)
    ops._find_node = lambda path: Node()
    return ops, borgfs.listxattr, borgfs.getxattr


@skipif_no_llfuse_api
def test_llfuse_listxattr():
    ops, listxattr, _ = llfuse_ops()
    assert listxattr(ops, 1) == XATTRS  # the low-level API uses bytes names


@skipif_no_llfuse_api
def test_llfuse_getxattr():
    ops, _, getxattr = llfuse_ops()
    assert getxattr(ops, 1, b"user.foo") == b"bar"


@skipif_no_llfuse_api
def test_llfuse_getxattr_missing():
    from ..fuse_impl import llfuse

    ops, _, getxattr = llfuse_ops(KeyError(b"user.foo"))
    with pytest.raises(llfuse.FUSEError) as excinfo:
        getxattr(ops, 1, b"user.foo")
    assert excinfo.value.errno == ENOATTR


@skipif_no_llfuse_api
def test_llfuse_getxattr_broken_acl():
    from ..fuse_impl import llfuse

    ops, _, getxattr = llfuse_ops(ValueError("can not convert this ACL"))
    with pytest.raises(llfuse.FUSEError) as excinfo:
        getxattr(ops, 1, b"system.posix_acl_access")
    assert excinfo.value.errno == errno.EIO


@skipif_no_mfusepy
def test_mfusepy_listxattr():
    ops, listxattr, _ = mfusepy_ops()
    # the high-level API uses str names
    assert listxattr(ops, "/file") == ["user.foo", "system.posix_acl_access"]


@skipif_no_mfusepy
def test_mfusepy_getxattr():
    ops, _, getxattr = mfusepy_ops()
    assert getxattr(ops, "/file", "user.foo") == b"bar"


@skipif_no_mfusepy
def test_mfusepy_getxattr_missing():
    from ..fuse_impl import hlfuse

    ops, _, getxattr = mfusepy_ops(KeyError(b"user.foo"))
    with pytest.raises(hlfuse.FuseOSError) as excinfo:
        getxattr(ops, "/file", "user.foo")
    assert excinfo.value.errno == ENOATTR


@skipif_no_mfusepy
def test_mfusepy_getxattr_broken_acl():
    from ..fuse_impl import hlfuse

    ops, _, getxattr = mfusepy_ops(ValueError("can not convert this ACL"))
    with pytest.raises(hlfuse.FuseOSError) as excinfo:
        getxattr(ops, "/file", "system.posix_acl_access")
    assert excinfo.value.errno == errno.EIO
