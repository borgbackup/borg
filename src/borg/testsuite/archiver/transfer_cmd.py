from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_transfer(self):
        def check_repo(repo_option):
            listing = self.cmd(repo_option, "rlist", "--short")
            assert "arch1" in listing
            assert "arch2" in listing
            listing = self.cmd(repo_option, "list", "--short", "arch1")
            assert "file1" in listing
            assert "dir2/file2" in listing
            self.cmd(repo_option, "check")

        self.create_test_files()
        repo1 = f"--repo={self.repository_location}1"
        repo2 = f"--repo={self.repository_location}2"
        other_repo1 = f"--other-repo={self.repository_location}1"

        self.cmd(repo1, "rcreate", RK_ENCRYPTION)
        self.cmd(repo1, "create", "arch1", "input")
        self.cmd(repo1, "create", "arch2", "input")
        check_repo(repo1)

        self.cmd(repo2, "rcreate", RK_ENCRYPTION, other_repo1)
        self.cmd(repo2, "transfer", other_repo1, "--dry-run")
        self.cmd(repo2, "transfer", other_repo1)
        self.cmd(repo2, "transfer", other_repo1, "--dry-run")
        check_repo(repo2)
