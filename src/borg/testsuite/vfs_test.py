"""Tests for the archive VFS core (vfs.py) that do not need a repository."""

import unicodedata

import pytest

from ..helpers import StableDict
from ..item import Item
from ..platform import acl_text_to_xattr
from ..vfs import VFSNode, item_getxattr, item_listxattr, lookup_child, versioned_name
from .platform.platform_test import skipif_not_linux

ACCESS_ACL = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:0\ngroup:root:rw-:0\n"
DEFAULT_ACL = b"user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:r--:0\ngroup:root:r--:0\n"
BROKEN_ACL = b"flubber::rw-\n"  # can not be converted to the binary xattr representation


def make_item(*, acls=True, acl_access=ACCESS_ACL):
    item = Item(path="file", mode=0o100666, mtime=0, xattrs=StableDict({b"user.foo": b"bar"}))
    if acls:
        item.acl_access = acl_access
        item.acl_default = DEFAULT_ACL
    return item


def make_dir(names):
    """Build a directory node with a leaf child for each name."""
    node = VFSNode(1, is_dir=True)
    for ino, name in enumerate(names, start=2):
        node.children[name] = VFSNode(ino, node)
    return node


def test_versioned_name():
    assert versioned_name("file.txt", 1) == "file.00001.txt"  # the extension stays at the end
    assert versioned_name("file", 42) == "file.00042"


def test_lookup_child():
    # exact matches always win, and names that are ambiguous after normalization are only
    # reachable by their exact spelling, so we never serve a different file than requested.
    nfc_name = "grüße.txt"  # composed
    nfd_name = unicodedata.normalize("NFD", nfc_name)  # decomposed
    assert nfc_name != nfd_name

    only_nfc = make_dir([nfc_name])
    # the stored (composed) name is found by both spellings
    assert lookup_child(only_nfc, nfc_name)[0] == nfc_name
    assert lookup_child(only_nfc, nfd_name)[0] == nfc_name

    only_nfd = make_dir([nfd_name])
    assert lookup_child(only_nfd, nfd_name)[0] == nfd_name
    assert lookup_child(only_nfd, nfc_name)[0] == nfd_name  # the other way round, too

    # an archive may contain both spellings (they are different names on e.g. Linux):
    # each one resolves to itself, exactly.
    both = make_dir([nfc_name, nfd_name])
    assert lookup_child(both, nfc_name)[0] == nfc_name
    assert lookup_child(both, nfd_name)[0] == nfd_name

    # a name with non-UTF-8 bytes (surrogate escapes) must not break normalization
    weird = b"bad\xff.txt".decode("utf-8", "surrogateescape")
    assert lookup_child(make_dir([weird]), weird)[0] == weird

    with pytest.raises(KeyError):
        lookup_child(only_nfc, "no-such-file.txt")

    with pytest.raises(KeyError):
        lookup_child(VFSNode(1), "anything")  # not a directory


# The ACL xattrs (see vfs.ACL_XATTRS) are emulated by the VFS, so we can test them by
# calling the xattr methods with a fake item. Unlike the tests in archiver/mount_cmds_test.py,
# this also works in environments where the kernel does not offer ACL xattrs on FUSE mounts
# (e.g. mounts made inside a user namespace). They are only emulated on Linux:


@skipif_not_linux
def test_listxattr_acls():
    names = item_listxattr(make_item())
    assert sorted(names) == [b"system.posix_acl_access", b"system.posix_acl_default", b"user.foo"]


@skipif_not_linux
def test_listxattr_no_acls():
    assert item_listxattr(make_item(acls=False)) == [b"user.foo"]


@skipif_not_linux
@pytest.mark.parametrize("numeric_ids", [False, True])
def test_getxattr_acls(numeric_ids):
    item = make_item()
    access = item_getxattr(item, b"system.posix_acl_access", numeric_ids=numeric_ids)
    assert access == acl_text_to_xattr(ACCESS_ACL, numeric_ids=numeric_ids)
    default = item_getxattr(item, b"system.posix_acl_default", numeric_ids=numeric_ids)
    assert default == acl_text_to_xattr(DEFAULT_ACL, numeric_ids=numeric_ids)
    assert item_getxattr(item, b"user.foo") == b"bar"  # "normal" xattrs still work


@skipif_not_linux
def test_getxattr_acl_missing():
    with pytest.raises(KeyError):
        item_getxattr(make_item(acls=False), b"system.posix_acl_access")


@skipif_not_linux
def test_getxattr_acl_broken():
    with pytest.raises(ValueError):
        item_getxattr(make_item(acl_access=BROKEN_ACL), b"system.posix_acl_access")


def test_getxattr_missing():
    with pytest.raises(KeyError):
        item_getxattr(make_item(), b"user.nope")
