import json
from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, RK_ENCRYPTION, checkts


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_info(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_repo = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "Original size:" in info_repo

    def test_info_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_repo = json.loads(self.cmd(f"--repo={self.repository_location}", "rinfo", "--json"))
        repository = info_repo["repository"]
        assert len(repository["id"]) == 64
        assert "last_modified" in repository
        checkts(repository["last_modified"])
        assert info_repo["encryption"]["mode"] == RK_ENCRYPTION[13:]
        assert "keyfile" not in info_repo["encryption"]
        cache = info_repo["cache"]
        stats = cache["stats"]
        assert all(isinstance(o, int) for o in stats.values())
        assert all(key in stats for key in ("total_chunks", "total_size", "total_unique_chunks", "unique_size"))
