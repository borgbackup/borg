import os
import tempfile
import unittest

from ..xattr import is_enabled, getxattr, setxattr, listxattr, buffer
from . import BaseTestCase


@unittest.skipUnless(is_enabled(), 'xattr not enabled on filesystem')
class XattrTestCase(BaseTestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()
        self.symlink = os.path.join(os.path.dirname(self.tmpfile.name), 'symlink')
        os.symlink(self.tmpfile.name, self.symlink)

    def tearDown(self):
        os.unlink(self.symlink)

    def assert_equal_se(self, is_x, want_x):
        # check 2 xattr lists for equality, but ignore security.selinux attr
        is_x = set(is_x) - {'security.selinux'}
        want_x = set(want_x)
        self.assert_equal(is_x, want_x)

    def test(self):
        self.assert_equal_se(listxattr(self.tmpfile.name), [])
        self.assert_equal_se(listxattr(self.tmpfile.fileno()), [])
        self.assert_equal_se(listxattr(self.symlink), [])
        setxattr(self.tmpfile.name, 'user.foo', b'bar')
        setxattr(self.tmpfile.fileno(), 'user.bar', b'foo')
        setxattr(self.tmpfile.name, 'user.empty', None)
        self.assert_equal_se(listxattr(self.tmpfile.name), ['user.foo', 'user.bar', 'user.empty'])
        self.assert_equal_se(listxattr(self.tmpfile.fileno()), ['user.foo', 'user.bar', 'user.empty'])
        self.assert_equal_se(listxattr(self.symlink), ['user.foo', 'user.bar', 'user.empty'])
        self.assert_equal_se(listxattr(self.symlink, follow_symlinks=False), [])
        self.assert_equal(getxattr(self.tmpfile.name, 'user.foo'), b'bar')
        self.assert_equal(getxattr(self.tmpfile.fileno(), 'user.foo'), b'bar')
        self.assert_equal(getxattr(self.symlink, 'user.foo'), b'bar')
        self.assert_equal(getxattr(self.tmpfile.name, 'user.empty'), None)

    def test_listxattr_buffer_growth(self):
        # make it work even with ext4, which imposes rather low limits
        buffer.resize(size=64, init=True)
        # xattr raw key list will be size 9 * (10 + 1), which is > 64
        keys = ['user.attr%d' % i for i in range(9)]
        for key in keys:
            setxattr(self.tmpfile.name, key, b'x')
        got_keys = listxattr(self.tmpfile.name)
        self.assert_equal_se(got_keys, keys)
        self.assert_equal(len(buffer), 128)

    def test_getxattr_buffer_growth(self):
        # make it work even with ext4, which imposes rather low limits
        buffer.resize(size=64, init=True)
        value = b'x' * 126
        setxattr(self.tmpfile.name, 'user.big', value)
        got_value = getxattr(self.tmpfile.name, 'user.big')
        self.assert_equal(value, got_value)
        self.assert_equal(len(buffer), 128)
