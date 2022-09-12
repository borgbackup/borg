import os

from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_delete_repo(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir2/file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")
        os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "no"
        self.cmd(f"--repo={self.repository_location}", "rdelete", exit_code=2)
        assert os.path.exists(self.repository_path)
        os.environ["BORG_DELETE_I_KNOW_WHAT_I_AM_DOING"] = "YES"
        self.cmd(f"--repo={self.repository_location}", "rdelete")
        # Make sure the repo is gone
        self.assertFalse(os.path.exists(self.repository_path))
