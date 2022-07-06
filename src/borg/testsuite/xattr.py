import os
import tempfile
import unittest

import pytest

from ..platform.xattr import buffer, split_lstring
from ..xattr import is_enabled, getxattr, setxattr, listxattr
from ..platformflags import is_linux
from . import BaseTestCase


@unittest.skipUnless(is_enabled(), "xattr not enabled on filesystem")
class XattrTestCase(BaseTestCase):
    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()
        self.symlink = self.tmpfile.name + ".symlink"
        os.symlink(self.tmpfile.name, self.symlink)

    def tearDown(self):
        os.unlink(self.symlink)

    def assert_equal_se(self, is_x, want_x):
        # check 2 xattr lists for equality, but ignore security.selinux attr
        is_x = set(is_x) - {b"security.selinux"}
        want_x = set(want_x)
        self.assert_equal(is_x, want_x)

    def test(self):
        tmp_fn = os.fsencode(self.tmpfile.name)
        tmp_lfn = os.fsencode(self.symlink)
        tmp_fd = self.tmpfile.fileno()
        self.assert_equal_se(listxattr(tmp_fn), [])
        self.assert_equal_se(listxattr(tmp_fd), [])
        self.assert_equal_se(listxattr(tmp_lfn), [])
        setxattr(tmp_fn, b"user.foo", b"bar")
        setxattr(tmp_fd, b"user.bar", b"foo")
        setxattr(tmp_fn, b"user.empty", b"")
        if not is_linux:
            # linux does not allow setting user.* xattrs on symlinks
            setxattr(tmp_lfn, b"user.linkxattr", b"baz")
        self.assert_equal_se(listxattr(tmp_fn), [b"user.foo", b"user.bar", b"user.empty"])
        self.assert_equal_se(listxattr(tmp_fd), [b"user.foo", b"user.bar", b"user.empty"])
        self.assert_equal_se(listxattr(tmp_lfn, follow_symlinks=True), [b"user.foo", b"user.bar", b"user.empty"])
        if not is_linux:
            self.assert_equal_se(listxattr(tmp_lfn), [b"user.linkxattr"])
        self.assert_equal(getxattr(tmp_fn, b"user.foo"), b"bar")
        self.assert_equal(getxattr(tmp_fd, b"user.foo"), b"bar")
        self.assert_equal(getxattr(tmp_lfn, b"user.foo", follow_symlinks=True), b"bar")
        if not is_linux:
            self.assert_equal(getxattr(tmp_lfn, b"user.linkxattr"), b"baz")
        self.assert_equal(getxattr(tmp_fn, b"user.empty"), b"")

    def test_listxattr_buffer_growth(self):
        tmp_fn = os.fsencode(self.tmpfile.name)
        # make it work even with ext4, which imposes rather low limits
        buffer.resize(size=64, init=True)
        # xattr raw key list will be > 64
        keys = [b"user.attr%d" % i for i in range(20)]
        for key in keys:
            setxattr(tmp_fn, key, b"x")
        got_keys = listxattr(tmp_fn)
        self.assert_equal_se(got_keys, keys)
        assert len(buffer) > 64

    def test_getxattr_buffer_growth(self):
        tmp_fn = os.fsencode(self.tmpfile.name)
        # make it work even with ext4, which imposes rather low limits
        buffer.resize(size=64, init=True)
        value = b"x" * 126
        setxattr(tmp_fn, b"user.big", value)
        got_value = getxattr(tmp_fn, b"user.big")
        self.assert_equal(value, got_value)
        self.assert_equal(len(buffer), 128)


@pytest.mark.parametrize(
    "lstring, splitted", ((b"", []), (b"\x00", [b""]), (b"\x01a", [b"a"]), (b"\x01a\x02cd", [b"a", b"cd"]))
)
def test_split_lstring(lstring, splitted):
    assert split_lstring(lstring) == splitted
