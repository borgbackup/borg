import os
import tempfile
import unittest
from darc.testsuite import DarcTestCase
from darc.xattr import lsetxattr, llistxattr, lgetxattr, get_all, set, flistxattr, fgetxattr, fsetxattr, is_enabled


@unittest.skipUnless(is_enabled(), 'xattr not enabled on filesystem')
class XattrTestCase(DarcTestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile()
        self.symlink = os.path.join(os.path.dirname(self.tmpfile.name), 'symlink')
        os.symlink(self.tmpfile.name, self.symlink)

    def tearDown(self):
        os.unlink(self.symlink)

    def test_low_level(self):
        self.assert_equal(llistxattr(self.tmpfile.name), [])
        self.assert_equal(llistxattr(self.symlink), [])
        lsetxattr(self.tmpfile.name, b'foo', b'bar')
        self.assert_equal(llistxattr(self.tmpfile.name), [b'foo'])
        self.assert_equal(lgetxattr(self.tmpfile.name, b'foo'), b'bar')
        self.assert_equal(llistxattr(self.symlink), [])

    def test_low_level_fileno(self):
        self.assert_equal(flistxattr(self.tmpfile.fileno()), [])
        fsetxattr(self.tmpfile.fileno(), b'foo', b'bar')
        self.assert_equal(flistxattr(self.tmpfile.fileno()), [b'foo'])
        self.assert_equal(fgetxattr(self.tmpfile.fileno(), b'foo'), b'bar')

    def test_high_level(self):
        self.assert_equal(get_all(self.tmpfile.name), {})
        self.assert_equal(get_all(self.symlink), {})
        set(self.tmpfile.name, b'foo', b'bar')
        self.assert_equal(get_all(self.tmpfile.name), {b'foo': b'bar'})
        self.assert_equal(get_all(self.symlink), {})

    def test_high_level_fileno(self):
        self.assert_equal(get_all(self.tmpfile.fileno()), {})
        set(self.tmpfile.fileno(), b'foo', b'bar')
        self.assert_equal(get_all(self.tmpfile.fileno()), {b'foo': b'bar'})
