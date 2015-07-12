import os
import tempfile
import unittest

from ..locking import UpgradableLock
from . import BaseTestCase


class UpgradableLockTestCase(BaseTestCase):

    def test(self):
        file = tempfile.NamedTemporaryFile()
        lock = UpgradableLock(file.name)
        lock.upgrade()
        lock.upgrade()
        lock.release()

    @unittest.skipIf(os.getuid() == 0, 'Root can always open files for writing')
    def test_read_only_lock_file(self):
        file = tempfile.NamedTemporaryFile()
        os.chmod(file.name, 0o444)
        lock = UpgradableLock(file.name)
        self.assert_raises(UpgradableLock.WriteLockFailed, lock.upgrade)
        lock.release()
