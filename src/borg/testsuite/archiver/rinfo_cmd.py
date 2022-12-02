import json
from random import randbytes
import unittest

from ...constants import *  # NOQA
from . import (
    ArchiverTestCaseBase,
    RemoteArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RK_ENCRYPTION,
    BORG_EXES,
    checkts,
)


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

    def test_info_on_repository_with_storage_quota(self):
        self.create_regular_file("file1", contents=randbytes(1000 * 1000))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION, "--storage-quota=1G")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_repo = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "Storage quota: 1.00 MB used out of 1.00 GB" in info_repo

    def test_info_on_repository_without_storage_quota(self):
        self.create_regular_file("file1", contents=randbytes(1000 * 1000))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_repo = self.cmd(f"--repo={self.repository_location}", "rinfo")
        assert "Storage quota: 1.00 MB used" in info_repo


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
