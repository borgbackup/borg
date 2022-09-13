import unittest

from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_rename(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir2/file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")
        self.cmd(f"--repo={self.repository_location}", "extract", "test", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.2", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "rename", "test", "test.3")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.2", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "rename", "test.2", "test.4")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.3", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.4", "--dry-run")
        # Make sure both archives have been renamed
        with Repository(self.repository_path) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        self.assert_equal(len(manifest.archives), 2)
        self.assert_in("test.3", manifest.archives)
        self.assert_in("test.4", manifest.archives)


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
