import os
import re
import unittest
from datetime import datetime

import pytest

from ...constants import *  # NOQA
from .. import changedir, are_hardlinks_supported
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_recreate_exclude_caches(self):
        self._create_test_caches()
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test", "--exclude-caches")
        self._assert_test_caches()

    def test_recreate_exclude_tagged(self):
        self._create_test_tagged()
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(
            f"--repo={self.repository_location}",
            "recreate",
            "-a",
            "test",
            "--exclude-if-present",
            ".NOBACKUP",
            "--exclude-if-present",
            "00-NOBACKUP",
        )
        self._assert_test_tagged()

    def test_recreate_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.cmd(
            f"--repo={self.repository_location}",
            "recreate",
            "-a",
            "test",
            "--exclude-if-present",
            ".NOBACKUP1",
            "--exclude-if-present",
            ".NOBACKUP2",
            "--exclude-caches",
            "--keep-exclude-tags",
        )
        self._assert_test_keep_tagged()

    @pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
    def test_recreate_hardlinked_tags(self):  # test for issue #4911
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.create_regular_file("file1", contents=CACHE_TAG_CONTENTS)  # "wrong" filename, but correct tag contents
        os.mkdir(os.path.join(self.input_path, "subdir"))  # to make sure the tag is encountered *after* file1
        os.link(
            os.path.join(self.input_path, "file1"), os.path.join(self.input_path, "subdir", CACHE_TAG_NAME)
        )  # correct tag name, hardlink to file1
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        # in the "test" archive, we now have, in this order:
        # - a regular file item for "file1"
        # - a hardlink item for "CACHEDIR.TAG" referring back to file1 for its contents
        self.cmd(f"--repo={self.repository_location}", "recreate", "test", "--exclude-caches", "--keep-exclude-tags")
        # if issue #4911 is present, the recreate will crash with a KeyError for "input/file1"

    def test_recreate_target_rc(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "recreate", "--target=asdf", exit_code=2)
        assert "Need to specify single archive" in output

    def test_recreate_target(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.check_cache()
        self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")
        self.check_cache()
        original_archive = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.cmd(
            f"--repo={self.repository_location}",
            "recreate",
            "test0",
            "input/dir2",
            "-e",
            "input/dir2/file3",
            "--target=new-archive",
        )
        self.check_cache()
        archives = self.cmd(f"--repo={self.repository_location}", "rlist")
        assert original_archive in archives
        assert "new-archive" in archives

        listing = self.cmd(f"--repo={self.repository_location}", "list", "new-archive", "--short")
        assert "file1" not in listing
        assert "dir2/file2" in listing
        assert "dir2/file3" not in listing

    def test_recreate_basic(self):
        self.create_test_files()
        self.create_regular_file("dir2/file3", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")
        self.cmd(f"--repo={self.repository_location}", "recreate", "test0", "input/dir2", "-e", "input/dir2/file3")
        self.check_cache()
        listing = self.cmd(f"--repo={self.repository_location}", "list", "test0", "--short")
        assert "file1" not in listing
        assert "dir2/file2" in listing
        assert "dir2/file3" not in listing

    @pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
    def test_recreate_subtree_hardlinks(self):
        # This is essentially the same problem set as in test_extract_hardlinks
        self._extract_hardlinks_setup()
        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test", "input/dir1")
        self.check_cache()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert os.stat("input/dir1/hardlink").st_nlink == 2
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
            assert os.stat("input/dir1/aaaa").st_nlink == 2
            assert os.stat("input/dir1/source2").st_nlink == 2
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test2")
            assert os.stat("input/dir1/hardlink").st_nlink == 4

    def test_recreate_rechunkify(self):
        with open(os.path.join(self.input_path, "large_file"), "wb") as fd:
            fd.write(b"a" * 280)
            fd.write(b"b" * 280)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", "input", "--chunker-params", "7,9,8,128")
        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input", "--files-cache=disabled")
        list = self.cmd(
            f"--repo={self.repository_location}",
            "list",
            "test1",
            "input/large_file",
            "--format",
            "{num_chunks} {unique_chunks}",
        )
        num_chunks, unique_chunks = map(int, list.split(" "))
        # test1 and test2 do not deduplicate
        assert num_chunks == unique_chunks
        self.cmd(f"--repo={self.repository_location}", "recreate", "--chunker-params", "default")
        self.check_cache()
        # test1 and test2 do deduplicate after recreate
        assert int(
            self.cmd(f"--repo={self.repository_location}", "list", "test1", "input/large_file", "--format={size}")
        )
        assert not int(
            self.cmd(
                f"--repo={self.repository_location}", "list", "test1", "input/large_file", "--format", "{unique_chunks}"
            )
        )

    def test_recreate_fixed_rechunkify(self):
        with open(os.path.join(self.input_path, "file"), "wb") as fd:
            fd.write(b"a" * 8192)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--chunker-params", "7,9,8,128")
        output = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "input/file", "--format", "{num_chunks}"
        )
        num_chunks = int(output)
        assert num_chunks > 2
        self.cmd(f"--repo={self.repository_location}", "recreate", "--chunker-params", "fixed,4096")
        output = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "input/file", "--format", "{num_chunks}"
        )
        num_chunks = int(output)
        assert num_chunks == 2

    def test_recreate_recompress(self):
        self.create_regular_file("compressible", size=10000)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "-C", "none")
        file_list = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "input/compressible", "--format", "{size} {sha256}"
        )
        size, sha256_before = file_list.split(" ")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-C", "lz4", "--recompress")
        self.check_cache()
        file_list = self.cmd(
            f"--repo={self.repository_location}", "list", "test", "input/compressible", "--format", "{size} {sha256}"
        )
        size, sha256_after = file_list.split(" ")
        assert sha256_before == sha256_after

    def test_recreate_timestamp(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")
        self.cmd(
            f"--repo={self.repository_location}",
            "recreate",
            "test0",
            "--timestamp",
            "1970-01-02T00:00:00",
            "--comment",
            "test",
        )
        info = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test0").splitlines()
        dtime = datetime(1970, 1, 2, 0, 0, 0).astimezone()  # local time in local timezone
        s_time = dtime.strftime("%Y-%m-%d %H:%M:.. %z").replace("+", r"\+")
        assert any([re.search(r"Time \(start\).+ %s" % s_time, item) for item in info])
        assert any([re.search(r"Time \(end\).+ %s" % s_time, item) for item in info])

    def test_recreate_dry_run(self):
        self.create_regular_file("compressible", size=10000)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        archives_before = self.cmd(f"--repo={self.repository_location}", "list", "test")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-n", "-e", "input/compressible")
        self.check_cache()
        archives_after = self.cmd(f"--repo={self.repository_location}", "list", "test")
        assert archives_after == archives_before

    def test_recreate_skips_nothing_to_do(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        info_before = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")
        self.cmd(f"--repo={self.repository_location}", "recreate", "--chunker-params", "default")
        self.check_cache()
        info_after = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")
        assert info_before == info_after  # includes archive ID

    def test_recreate_list_output(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=0)
        self.create_regular_file("file2", size=0)
        self.create_regular_file("file3", size=0)
        self.create_regular_file("file4", size=0)
        self.create_regular_file("file5", size=0)

        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        output = self.cmd(
            f"--repo={self.repository_location}", "recreate", "-a", "test", "--list", "--info", "-e", "input/file2"
        )
        self.check_cache()
        self.assert_in("input/file1", output)
        self.assert_in("- input/file2", output)

        output = self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test", "--list", "-e", "input/file3")
        self.check_cache()
        self.assert_in("input/file1", output)
        self.assert_in("- input/file3", output)

        output = self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test", "-e", "input/file4")
        self.check_cache()
        self.assert_not_in("input/file1", output)
        self.assert_not_in("- input/file4", output)

        output = self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test", "--info", "-e", "input/file5")
        self.check_cache()
        self.assert_not_in("input/file1", output)
        self.assert_not_in("- input/file5", output)

    def test_comment(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test2", "input", "--comment", "this is the comment")
        self.cmd(f"--repo={self.repository_location}", "create", "test3", "input", "--comment", '"deleted" comment')
        self.cmd(f"--repo={self.repository_location}", "create", "test4", "input", "--comment", "preserved comment")
        assert "Comment: " + os.linesep in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test1")
        assert "Comment: this is the comment" in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test2")

        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test1", "--comment", "added comment")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test2", "--comment", "modified comment")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test3", "--comment", "")
        self.cmd(f"--repo={self.repository_location}", "recreate", "-a", "test4", "12345")
        assert "Comment: added comment" in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test1")
        assert "Comment: modified comment" in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test2")
        assert "Comment: " + os.linesep in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test3")
        assert "Comment: preserved comment" in self.cmd(f"--repo={self.repository_location}", "info", "-a", "test4")


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
