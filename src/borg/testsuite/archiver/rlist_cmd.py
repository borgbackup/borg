import json
import unittest

from ...constants import *  # NOQA
from . import (
    ArchiverTestCaseBase,
    RemoteArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    src_dir,
    RK_ENCRYPTION,
    checkts,
    BORG_EXES,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_rlist_glob(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test-1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "something-else-than-test-1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test-2", src_dir)
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--match-archives=sh:test-*")
        self.assert_in("test-1", output)
        self.assert_in("test-2", output)
        self.assert_not_in("something-else", output)

    def test_archives_format(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--comment", "comment 1", "test-1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "--comment", "comment 2", "test-2", src_dir)
        output_1 = self.cmd(f"--repo={self.repository_location}", "rlist")
        output_2 = self.cmd(
            f"--repo={self.repository_location}", "rlist", "--format", "{archive:<36} {time} [{id}]{NL}"
        )
        self.assertEqual(output_1, output_2)
        output_1 = self.cmd(f"--repo={self.repository_location}", "rlist", "--short")
        self.assertEqual(output_1, "test-1\ntest-2\n")
        output_1 = self.cmd(f"--repo={self.repository_location}", "rlist", "--format", "{barchive}/")
        self.assertEqual(output_1, "test-1/test-2/")
        output_3 = self.cmd(f"--repo={self.repository_location}", "rlist", "--format", "{name} {comment}{NL}")
        self.assert_in("test-1 comment 1\n", output_3)
        self.assert_in("test-2 comment 2\n", output_3)

    def test_rlist_consider_checkpoints(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", src_dir)
        # these are not really a checkpoints, but they look like some:
        self.cmd(f"--repo={self.repository_location}", "create", "test2.checkpoint", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test3.checkpoint.1", src_dir)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        assert "test1" in output
        assert "test2.checkpoint" not in output
        assert "test3.checkpoint.1" not in output
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--consider-checkpoints")
        assert "test1" in output
        assert "test2.checkpoint" in output
        assert "test3.checkpoint.1" in output

    def test_rlist_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        list_repo = json.loads(self.cmd(f"--repo={self.repository_location}", "rlist", "--json"))
        repository = list_repo["repository"]
        assert len(repository["id"]) == 64
        checkts(repository["last_modified"])
        assert list_repo["encryption"]["mode"] == RK_ENCRYPTION[13:]
        assert "keyfile" not in list_repo["encryption"]
        archive0 = list_repo["archives"][0]
        checkts(archive0["time"])


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
