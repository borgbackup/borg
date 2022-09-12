import json
from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION, checkts


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_info(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_archive = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")
        assert "Archive name: test\n" in info_archive
        info_archive = self.cmd(f"--repo={self.repository_location}", "info", "--first", "1")
        assert "Archive name: test\n" in info_archive

    def test_info_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        info_archive = json.loads(self.cmd(f"--repo={self.repository_location}", "info", "-a", "test", "--json"))
        archives = info_archive["archives"]
        assert len(archives) == 1
        archive = archives[0]
        assert archive["name"] == "test"
        assert isinstance(archive["command_line"], list)
        assert isinstance(archive["duration"], float)
        assert len(archive["id"]) == 64
        assert "stats" in archive
        checkts(archive["start"])
        checkts(archive["end"])

    def test_info_json_of_empty_archive(self):
        """See https://github.com/borgbackup/borg/issues/6120"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        info_repo = json.loads(self.cmd(f"--repo={self.repository_location}", "info", "--json", "--first=1"))
        assert info_repo["archives"] == []
        info_repo = json.loads(self.cmd(f"--repo={self.repository_location}", "info", "--json", "--last=1"))
        assert info_repo["archives"] == []
