import os
from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_break_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "break-lock")

    def test_with_lock(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        lock_path = os.path.join(self.repository_path, "lock.exclusive")
        cmd = "python3", "-c", 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
        self.cmd(f"--repo={self.repository_location}", "with-lock", *cmd, fork=True, exit_code=42)
