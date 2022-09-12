import json
import os

from ...constants import *  # NOQA
from . import ArchiverTestCaseBase, src_dir, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_list_format(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", src_dir)
        output_1 = self.cmd(f"--repo={self.repository_location}", "list", "test")
        output_2 = self.cmd(
            f"--repo={self.repository_location}",
            "list",
            "test",
            "--format",
            "{mode} {user:6} {group:6} {size:8d} {mtime} {path}{extra}{NEWLINE}",
        )
        output_3 = self.cmd(f"--repo={self.repository_location}", "list", "test", "--format", "{mtime:%s} {path}{NL}")
        self.assertEqual(output_1, output_2)
        self.assertNotEqual(output_1, output_3)

    def test_list_hash(self):
        self.create_regular_file("empty_file", size=0)
        self.create_regular_file("amb", contents=b"a" * 1000000)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test", "--format", "{sha256} {path}{NL}")
        assert "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 input/amb" in output
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 input/empty_file" in output

    def test_list_chunk_counts(self):
        self.create_regular_file("empty_file", size=0)
        self.create_regular_file("two_chunks")
        with open(os.path.join(self.input_path, "two_chunks"), "wb") as fd:
            fd.write(b"abba" * 2000000)
            fd.write(b"baab" * 2000000)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        output = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "--format", "{num_chunks} {unique_chunks} {path}{NL}"
        )
        assert "0 0 input/empty_file" in output
        assert "2 2 input/two_chunks" in output

    def test_list_size(self):
        self.create_regular_file("compressible_file", size=10000)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "-C", "lz4", "test", "input")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test", "--format", "{size} {path}{NL}")
        size, path = output.split("\n")[1].split(" ")
        assert int(size) == 10000

    def test_list_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        list_archive = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        items = [json.loads(s) for s in list_archive.splitlines()]
        assert len(items) == 2
        file1 = items[1]
        assert file1["path"] == "input/file1"
        assert file1["size"] == 81920

        list_archive = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "--json-lines", "--format={sha256}"
        )
        items = [json.loads(s) for s in list_archive.splitlines()]
        assert len(items) == 2
        file1 = items[1]
        assert file1["path"] == "input/file1"
        assert file1["sha256"] == "b2915eb69f260d8d3c25249195f2c8f4f716ea82ec760ae929732c0262442b2b"
