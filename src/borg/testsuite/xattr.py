import os
import tempfile
import unittest

from ..xattr import is_enabled, getxattr, setxattr, listxattr
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
