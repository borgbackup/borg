import unittest

from ...archive import Archive
from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES
from . import src_file


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_delete(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir2/file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test.3", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "another_test.1", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "another_test.2", "input")
        self.cmd(f"--repo={self.repository_location}", "extract", "test", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.2", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "delete", "--match-archives", "sh:another_*")
        self.cmd(f"--repo={self.repository_location}", "delete", "--last", "1")
        self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test")
        self.cmd(f"--repo={self.repository_location}", "extract", "test.2", "--dry-run")
        output = self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test.2", "--stats")
        self.assert_in("Original size: -", output)  # negative size == deleted data
        # Make sure all data except the manifest has been deleted
        with Repository(self.repository_path) as repository:
            self.assert_equal(len(repository), 1)

    def test_delete_multiple(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test3", "input")
        self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test1")
        self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test2")
        self.cmd(f"--repo={self.repository_location}", "extract", "test3", "--dry-run")
        self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test3")
        assert not self.cmd(f"--repo={self.repository_location}", "rlist")

    def test_delete_force(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.create_src_archive("test")
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(manifest, "test")
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    repository.delete(item.chunks[-1].id)
                    break
            else:
                assert False  # missed the file
            repository.commit(compact=False)
        output = self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test", "--force")
        self.assert_in("deleted archive was corrupted", output)
        self.cmd(f"--repo={self.repository_location}", "check", "--repair")
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_not_in("test", output)

    def test_delete_double_force(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.create_src_archive("test")
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(manifest, "test")
            id = archive.metadata.items[0]
            repository.put(id, b"corrupted items metadata stream chunk")
            repository.commit(compact=False)
        self.cmd(f"--repo={self.repository_location}", "delete", "-a", "test", "--force", "--force")
        self.cmd(f"--repo={self.repository_location}", "check", "--repair")
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_not_in("test", output)


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
