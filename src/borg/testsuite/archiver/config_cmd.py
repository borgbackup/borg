import os
import unittest

from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_config(self):
        self.create_test_files()
        os.unlink("input/flagfile")
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "config", "--list")
        self.assert_in("[repository]", output)
        self.assert_in("version", output)
        self.assert_in("segments_per_dir", output)
        self.assert_in("storage_quota", output)
        self.assert_in("append_only", output)
        self.assert_in("additional_free_space", output)
        self.assert_in("id", output)
        self.assert_not_in("last_segment_checked", output)

        output = self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked", exit_code=1)
        self.assert_in("No option ", output)
        self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked", "123")
        output = self.cmd(f"--repo={self.repository_location}", "config", "last_segment_checked")
        assert output == "123" + "\n"
        output = self.cmd(f"--repo={self.repository_location}", "config", "--list")
        self.assert_in("last_segment_checked", output)
        self.cmd(f"--repo={self.repository_location}", "config", "--delete", "last_segment_checked")

        for cfg_key, cfg_value in [("additional_free_space", "2G"), ("repository.append_only", "1")]:
            output = self.cmd(f"--repo={self.repository_location}", "config", cfg_key)
            assert output == "0" + "\n"
            self.cmd(f"--repo={self.repository_location}", "config", cfg_key, cfg_value)
            output = self.cmd(f"--repo={self.repository_location}", "config", cfg_key)
            assert output == cfg_value + "\n"
            self.cmd(f"--repo={self.repository_location}", "config", "--delete", cfg_key)
            self.cmd(f"--repo={self.repository_location}", "config", cfg_key, exit_code=1)

        self.cmd(f"--repo={self.repository_location}", "config", "--list", "--delete", exit_code=2)
        self.cmd(f"--repo={self.repository_location}", "config", exit_code=2)
        self.cmd(f"--repo={self.repository_location}", "config", "invalid-option", exit_code=1)


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
