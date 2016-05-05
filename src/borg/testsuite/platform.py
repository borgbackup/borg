import os
import shutil
import sys
import tempfile
import unittest

from ..platform import acl_get, acl_set
from . import BaseTestCase


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


@unittest.skipUnless(sys.platform.startswith('linux'), 'linux only test')
@unittest.skipIf(fakeroot_detected(), 'not compatible with fakeroot')
class PlatformLinuxTestCase(BaseTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def get_acl(self, path, numeric_owner=False):
        item = {}
        acl_get(path, item, os.stat(path), numeric_owner=numeric_owner)
        return item

    def set_acl(self, path, access=None, default=None, numeric_owner=False):
        item = {b'acl_access': access, b'acl_default': default}
        acl_set(path, item, numeric_owner=numeric_owner)

    def test_access_acl(self):
        file = tempfile.NamedTemporaryFile()
        self.assert_equal(self.get_acl(file.name), {})
        self.set_acl(file.name, access=b'user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n', numeric_owner=False)
        self.assert_in(b'user:root:rw-:0', self.get_acl(file.name)[b'acl_access'])
        self.assert_in(b'group:root:rw-:0', self.get_acl(file.name)[b'acl_access'])
        self.assert_in(b'user:0:rw-:0', self.get_acl(file.name, numeric_owner=True)[b'acl_access'])
        file2 = tempfile.NamedTemporaryFile()
        self.set_acl(file2.name, access=b'user::rw-\ngroup::r--\nmask::rw-\nother::---\nuser:root:rw-:9999\ngroup:root:rw-:9999\n', numeric_owner=True)
        self.assert_in(b'user:9999:rw-:9999', self.get_acl(file2.name)[b'acl_access'])
        self.assert_in(b'group:9999:rw-:9999', self.get_acl(file2.name)[b'acl_access'])

    def test_default_acl(self):
        self.assert_equal(self.get_acl(self.tmpdir), {})
        self.set_acl(self.tmpdir, access=ACCESS_ACL, default=DEFAULT_ACL)
        self.assert_equal(self.get_acl(self.tmpdir)[b'acl_access'], ACCESS_ACL)
        self.assert_equal(self.get_acl(self.tmpdir)[b'acl_default'], DEFAULT_ACL)

    def test_non_ascii_acl(self):
        # Testing non-ascii ACL processing to see whether our code is robust.
        # I have no idea whether non-ascii ACLs are allowed by the standard,
        # but in practice they seem to be out there and must not make our code explode.
        file = tempfile.NamedTemporaryFile()
        self.assert_equal(self.get_acl(file.name), {})
        nothing_special = 'user::rw-\ngroup::r--\nmask::rw-\nother::---\n'.encode('ascii')
        # TODO: can this be tested without having an existing system user übel with uid 666 gid 666?
        user_entry = 'user:übel:rw-:666'.encode('utf-8')
        user_entry_numeric = 'user:666:rw-:666'.encode('ascii')
        group_entry = 'group:übel:rw-:666'.encode('utf-8')
        group_entry_numeric = 'group:666:rw-:666'.encode('ascii')
        acl = b'\n'.join([nothing_special, user_entry, group_entry])
        self.set_acl(file.name, access=acl, numeric_owner=False)
        acl_access = self.get_acl(file.name, numeric_owner=False)[b'acl_access']
        self.assert_in(user_entry, acl_access)
        self.assert_in(group_entry, acl_access)
        acl_access_numeric = self.get_acl(file.name, numeric_owner=True)[b'acl_access']
        self.assert_in(user_entry_numeric, acl_access_numeric)
        self.assert_in(group_entry_numeric, acl_access_numeric)
        file2 = tempfile.NamedTemporaryFile()
        self.set_acl(file2.name, access=acl, numeric_owner=True)
        acl_access = self.get_acl(file2.name, numeric_owner=False)[b'acl_access']
        self.assert_in(user_entry, acl_access)
        self.assert_in(group_entry, acl_access)
        acl_access_numeric = self.get_acl(file.name, numeric_owner=True)[b'acl_access']
        self.assert_in(user_entry_numeric, acl_access_numeric)
        self.assert_in(group_entry_numeric, acl_access_numeric)

    def test_utils(self):
        from ..platform_linux import acl_use_local_uid_gid
        self.assert_equal(acl_use_local_uid_gid(b'user:nonexistent1234:rw-:1234'), b'user:1234:rw-')
        self.assert_equal(acl_use_local_uid_gid(b'group:nonexistent1234:rw-:1234'), b'group:1234:rw-')
        self.assert_equal(acl_use_local_uid_gid(b'user:root:rw-:0'), b'user:0:rw-')
        self.assert_equal(acl_use_local_uid_gid(b'group:root:rw-:0'), b'group:0:rw-')


@unittest.skipUnless(sys.platform.startswith('darwin'), 'OS X only test')
@unittest.skipIf(fakeroot_detected(), 'not compatible with fakeroot')
class PlatformDarwinTestCase(BaseTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def get_acl(self, path, numeric_owner=False):
        item = {}
        acl_get(path, item, os.stat(path), numeric_owner=numeric_owner)
        return item

    def set_acl(self, path, acl, numeric_owner=False):
        item = {b'acl_extended': acl}
        acl_set(path, item, numeric_owner=numeric_owner)

    def test_access_acl(self):
        file = tempfile.NamedTemporaryFile()
        file2 = tempfile.NamedTemporaryFile()
        self.assert_equal(self.get_acl(file.name), {})
        self.set_acl(file.name, b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n', numeric_owner=False)
        self.assert_in(b'group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014:staff:20:allow:read', self.get_acl(file.name)[b'acl_extended'])
        self.assert_in(b'user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read', self.get_acl(file.name)[b'acl_extended'])
        self.set_acl(file2.name, b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\nuser:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n', numeric_owner=True)
        self.assert_in(b'group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:wheel:0:allow:read', self.get_acl(file2.name)[b'acl_extended'])
        self.assert_in(b'group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000::0:allow:read', self.get_acl(file2.name, numeric_owner=True)[b'acl_extended'])
