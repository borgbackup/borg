import os
import unittest

from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_break_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "break-lock")

    def test_with_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        lock_path = os.path.join(self.repository_path, "lock.exclusive")
        cmd = "python3", "-c", 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
        self.cmd(f"--repo={self.repository_location}", "with-lock", *cmd, fork=True, exit_code=42)


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
