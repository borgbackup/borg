import os
import shutil
import tempfile
import unittest
from attic.platform import acl_get, acl_set
from attic.testsuite import AtticTestCase


ACCESS_ACL = """
user::rw-
user:root:rw-:0
user:9999:r--:9999
group::r--
group:root:r--:0
group:9999:r--:9999
mask::rw-
other::r--
""".strip().encode('ascii')

DEFAULT_ACL = """
user::rw-
user:root:r--:0
user:8888:r--:8888
group::r--
group:root:r--:0
group:8888:r--:8888
mask::rw-
other::r--
""".strip().encode('ascii')


def fakeroot_detected():
    return 'FAKEROOTKEY' in os.environ


@unittest.skipIf(fakeroot_detected(), 'not compatible with fakeroot')
class PlatformLinuxTestCase(AtticTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def get_acl(self, path):
        item = {}
        acl_get(path, item)
        return item

    def set_acl(self, path, access=None, default=None):
        item = {b'acl_access': access, b'acl_default': default}
        acl_set(path, item)

    def test_access_acl(self):
        file = tempfile.NamedTemporaryFile()
        self.assert_equal(self.get_acl(file.name), {})
        self.set_acl(file.name, access=ACCESS_ACL)
        self.assert_equal(self.get_acl(file.name)[b'acl_access'], ACCESS_ACL)

    def test_default_acl(self):
        self.assert_equal(self.get_acl(self.tmpdir), {})
        self.set_acl(self.tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
        self.assert_equal(self.get_acl(self.tmpdir)[b'acl_access'], ACCESS_ACL)
        self.assert_equal(self.get_acl(self.tmpdir)[b'acl_default'], DEFAULT_ACL)

