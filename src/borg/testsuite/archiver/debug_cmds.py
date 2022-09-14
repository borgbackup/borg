import json
import os
import pstats
import unittest
from hashlib import sha256

from ...constants import *  # NOQA
from .. import changedir
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_debug_profile(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--debug-profile=create.prof")
        self.cmd("debug", "convert-profile", "create.prof", "create.pyprof")
        stats = pstats.Stats("create.pyprof")
        stats.strip_dirs()
        stats.sort_stats("cumtime")

        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input", "--debug-profile=create.pyprof")
        stats = pstats.Stats("create.pyprof")  # Only do this on trusted data!
        stats.strip_dirs()
        stats.sort_stats("cumtime")

    def test_debug_dump_archive_items(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "debug", "dump-archive-items", "test")
        output_dir = sorted(os.listdir("output"))
        assert len(output_dir) > 0 and output_dir[0].startswith("000000_")
        assert "Done." in output

    def test_debug_dump_repo_objs(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "debug", "dump-repo-objs")
        output_dir = sorted(os.listdir("output"))
        assert len(output_dir) > 0 and output_dir[0].startswith("00000000_")
        assert "Done." in output

    def test_debug_put_get_delete_obj(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        data = b"some data"
        hexkey = sha256(data).hexdigest()
        self.create_regular_file("file", contents=data)
        output = self.cmd(f"--repo={self.repository_location}", "debug", "put-obj", "input/file")
        assert hexkey in output
        output = self.cmd(f"--repo={self.repository_location}", "debug", "get-obj", hexkey, "output/file")
        assert hexkey in output
        with open("output/file", "rb") as f:
            data_read = f.read()
        assert data == data_read
        output = self.cmd(f"--repo={self.repository_location}", "debug", "delete-obj", hexkey)
        assert "deleted" in output
        output = self.cmd(f"--repo={self.repository_location}", "debug", "delete-obj", hexkey)
        assert "not found" in output
        output = self.cmd(f"--repo={self.repository_location}", "debug", "delete-obj", "invalid")
        assert "is invalid" in output

    def test_debug_dump_manifest(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        dump_file = self.output_path + "/dump"
        output = self.cmd(f"--repo={self.repository_location}", "debug", "dump-manifest", dump_file)
        assert output == ""
        with open(dump_file) as f:
            result = json.load(f)
        assert "archives" in result
        assert "config" in result
        assert "item_keys" in result
        assert "timestamp" in result
        assert "version" in result

    def test_debug_dump_archive(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        dump_file = self.output_path + "/dump"
        output = self.cmd(f"--repo={self.repository_location}", "debug", "dump-archive", "test", dump_file)
        assert output == ""
        with open(dump_file) as f:
            result = json.load(f)
        assert "_name" in result
        assert "_manifest_entry" in result
        assert "_meta" in result
        assert "_items" in result

    def test_debug_refcount_obj(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "debug", "refcount-obj", "0" * 64).strip()
        assert (
            output
            == "object 0000000000000000000000000000000000000000000000000000000000000000 not found [info from chunks cache]."
        )

        create_json = json.loads(self.cmd(f"--repo={self.repository_location}", "create", "--json", "test", "input"))
        archive_id = create_json["archive"]["id"]
        output = self.cmd(f"--repo={self.repository_location}", "debug", "refcount-obj", archive_id).strip()
        assert output == "object " + archive_id + " has 1 referrers [info from chunks cache]."

        # Invalid IDs do not abort or return an error
        output = self.cmd(f"--repo={self.repository_location}", "debug", "refcount-obj", "124", "xyza").strip()
        assert output == "object id 124 is invalid.\nobject id xyza is invalid."

    def test_debug_info(self):
        output = self.cmd("debug", "info")
        assert "Python" in output


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
