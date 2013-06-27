import tempfile
import os
from darc.testsuite import DarcTestCase
from darc.xattr import lsetxattr, llistxattr, lgetxattr, get_all, set, flistxattr, fgetxattr, fsetxattr


class XattrTestCase(DarcTestCase):

    def test_low_level(self):
        with tempfile.NamedTemporaryFile(dir=os.getcwd()) as fd:
            self.assert_equal(llistxattr(fd.name), [])
            lsetxattr(fd.name, b'user.foo', b'bar')
            self.assert_equal(llistxattr(fd.name), [b'user.foo'])
            self.assert_equal(lgetxattr(fd.name, b'user.foo'), b'bar')

    def test_low_level_fileno(self):
        with tempfile.NamedTemporaryFile(dir=os.getcwd()) as fd:
            self.assert_equal(flistxattr(fd.fileno()), [])
            fsetxattr(fd.fileno(), b'user.foo', b'bar')
            self.assert_equal(flistxattr(fd.fileno()), [b'user.foo'])
            self.assert_equal(fgetxattr(fd.fileno(), b'user.foo'), b'bar')

    def test_high_level(self):
        with tempfile.NamedTemporaryFile(dir=os.getcwd()) as fd:
            self.assert_equal(get_all(fd.name), {})
            set(fd.name, b'foo', b'bar')
            self.assert_equal(get_all(fd.name), {b'foo': b'bar'})

    def test_high_level_fileno(self):
        with tempfile.NamedTemporaryFile(dir=os.getcwd()) as fd:
            self.assert_equal(get_all(fd.fileno()), {})
            set(fd.fileno(), b'foo', b'bar')
            self.assert_equal(get_all(fd.fileno()), {b'foo': b'bar'})
