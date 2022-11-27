import errno
import json
import os
from random import randbytes
import shutil
import socket
import stat
import time
import unittest

import pytest

from ... import platform
from ...constants import *  # NOQA
from ...manifest import Manifest
from ...platform import is_cygwin, is_win32
from ...repository import Repository
from .. import has_lchflags
from .. import changedir
from .. import (
    are_symlinks_supported,
    are_hardlinks_supported,
    are_fifos_supported,
    is_utime_fully_supported,
    is_birthtime_fully_supported,
)
from . import (
    ArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RemoteArchiverTestCaseBase,
    RK_ENCRYPTION,
    BORG_EXES,
    requires_hardlinks,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_basic_functionality(self):
        have_root = self.create_test_files()
        # fork required to test show-rc output
        output = self.cmd(
            f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION, "--show-version", "--show-rc", fork=True
        )
        self.assert_in("borgbackup version", output)
        self.assert_in("terminating with success status, rc 0", output)
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude-nodump", "test", "input")
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--exclude-nodump", "--stats", "test.2", "input"
        )
        self.assert_in("Archive name: test.2", output)
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        list_output = self.cmd(f"--repo={self.repository_location}", "rlist", "--short")
        self.assert_in("test", list_output)
        self.assert_in("test.2", list_output)
        expected = [
            "input",
            "input/bdev",
            "input/cdev",
            "input/dir2",
            "input/dir2/file2",
            "input/empty",
            "input/file1",
            "input/flagfile",
        ]
        if are_fifos_supported():
            expected.append("input/fifo1")
        if are_symlinks_supported():
            expected.append("input/link1")
        if are_hardlinks_supported():
            expected.append("input/hardlink")
        if not have_root:
            # we could not create these device files without (fake)root
            expected.remove("input/bdev")
            expected.remove("input/cdev")
        if has_lchflags:
            # remove the file we did not backup, so input and output become equal
            expected.remove("input/flagfile")  # this file is UF_NODUMP
            os.remove(os.path.join("input", "flagfile"))
        list_output = self.cmd(f"--repo={self.repository_location}", "list", "test", "--short")
        for name in expected:
            self.assert_in(name, list_output)
        self.assert_dirs_equal("input", "output/input")
        info_output = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")
        item_count = 5 if has_lchflags else 6  # one file is UF_NODUMP
        self.assert_in("Number of files: %d" % item_count, info_output)
        shutil.rmtree(self.cache_path)
        info_output2 = self.cmd(f"--repo={self.repository_location}", "info", "-a", "test")

        def filter(output):
            # filter for interesting "info" output, ignore cache rebuilding related stuff
            prefixes = ["Name:", "Fingerprint:", "Number of files:", "This archive:", "All archives:", "Chunk index:"]
            result = []
            for line in output.splitlines():
                for prefix in prefixes:
                    if line.startswith(prefix):
                        result.append(line)
            return "\n".join(result)

        # the interesting parts of info_output2 and info_output should be same
        self.assert_equal(filter(info_output), filter(info_output2))

    @requires_hardlinks
    def test_create_duplicate_root(self):
        # setup for #5603
        path_a = os.path.join(self.input_path, "a")
        path_b = os.path.join(self.input_path, "b")
        os.mkdir(path_a)
        os.mkdir(path_b)
        hl_a = os.path.join(path_a, "hardlink")
        hl_b = os.path.join(path_b, "hardlink")
        self.create_regular_file(hl_a, contents=b"123456")
        os.link(hl_a, hl_b)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "input")  # give input twice!
        # test if created archive has 'input' contents twice:
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        # we have all fs items exactly once!
        assert sorted(paths) == ["input", "input/a", "input/a/hardlink", "input/b", "input/b/hardlink"]

    @pytest.mark.skipif(is_win32, reason="unix sockets not available on windows")
    def test_unix_socket(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(os.path.join(self.input_path, "unix-socket"))
        except PermissionError as err:
            if err.errno == errno.EPERM:
                pytest.skip("unix sockets disabled or not supported")
            elif err.errno == errno.EACCES:
                pytest.skip("permission denied to create unix sockets")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        sock.close()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert not os.path.exists("input/unix-socket")

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    @pytest.mark.skipif(
        not is_birthtime_fully_supported(), reason="cannot properly setup and execute test without birthtime"
    )
    def test_nobirthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime("input/file1", (atime, birthtime))
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--nobirthtime")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert int(sti.st_birthtime * 1e9) == birthtime * 1e9
        assert int(sto.st_birthtime * 1e9) == mtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

    def test_create_stdin(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        input_data = b"\x00foo\n\nbar\n   \n"
        self.cmd(f"--repo={self.repository_location}", "create", "test", "-", input=input_data)
        item = json.loads(self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines"))
        assert item["uid"] == 0
        assert item["gid"] == 0
        assert item["size"] == len(input_data)
        assert item["path"] == "stdin"
        extracted_data = self.cmd(
            f"--repo={self.repository_location}", "extract", "test", "--stdout", binary_output=True
        )
        assert extracted_data == input_data

    def test_create_content_from_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        input_data = "some test content"
        name = "a/b/c"
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--stdin-name",
            name,
            "--content-from-command",
            "test",
            "--",
            "echo",
            input_data,
        )
        item = json.loads(self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines"))
        assert item["uid"] == 0
        assert item["gid"] == 0
        assert item["size"] == len(input_data) + 1  # `echo` adds newline
        assert item["path"] == name
        extracted_data = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--stdout")
        assert extracted_data == input_data + "\n"

    def test_create_content_from_command_with_failed_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--content-from-command",
            "test",
            "--",
            "sh",
            "-c",
            "exit 73;",
            exit_code=2,
        )
        assert output.endswith("Command 'sh' exited with status 73" + os.linesep)
        archive_list = json.loads(self.cmd(f"--repo={self.repository_location}", "rlist", "--json"))
        assert archive_list["archives"] == []

    def test_create_content_from_command_missing_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "--content-from-command", exit_code=2)
        assert output.endswith("No command given." + os.linesep)

    def test_create_paths_from_stdin(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir1/file2", size=1024 * 80)
        self.create_regular_file("dir1/file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)

        input_data = b"input/file1\0input/dir1\0input/file4"
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "--paths-from-stdin",
            "--paths-delimiter",
            "\\0",
            input=input_data,
        )
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        assert paths == ["input/file1", "input/dir1", "input/file4"]

    def test_create_paths_from_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)

        input_data = "input/file1\ninput/file2\ninput/file3"
        self.cmd(
            f"--repo={self.repository_location}", "create", "--paths-from-command", "test", "--", "echo", input_data
        )
        archive_list = self.cmd(f"--repo={self.repository_location}", "list", "test", "--json-lines")
        paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
        assert paths == ["input/file1", "input/file2", "input/file3"]

    def test_create_paths_from_command_with_failed_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--paths-from-command",
            "test",
            "--",
            "sh",
            "-c",
            "exit 73;",
            exit_code=2,
        )
        assert output.endswith("Command 'sh' exited with status 73" + os.linesep)
        archive_list = json.loads(self.cmd(f"--repo={self.repository_location}", "rlist", "--json"))
        assert archive_list["archives"] == []

    def test_create_paths_from_command_missing_command(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "--paths-from-command", exit_code=2)
        assert output.endswith("No command given." + os.linesep)

    def test_create_without_root(self):
        """test create without a root"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", exit_code=2)

    def test_create_pattern_root(self):
        """test create with only a root pattern"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "-v", "--list", "--pattern=R input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)

    def test_create_pattern(self):
        """test file patterns during create"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--pattern=+input/file_important",
            "--pattern=-input/file*",
            "test",
            "input",
        )
        self.assert_in("A input/file_important", output)
        self.assert_in("x input/file1", output)
        self.assert_in("x input/file2", output)

    def test_create_pattern_file(self):
        """test file patterns during create"""
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("otherfile", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--pattern=-input/otherfile",
            "--patterns-from=" + self.patterns_file_path,
            "test",
            "input",
        )
        self.assert_in("A input/file_important", output)
        self.assert_in("x input/file1", output)
        self.assert_in("x input/file2", output)
        self.assert_in("x input/otherfile", output)

    def test_create_pattern_exclude_folder_but_recurse(self):
        """test when patterns exclude a parent folder, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/b\n- input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        self.create_regular_file("y/foo_y", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--patterns-from=" + self.patterns_file_path2,
            "test",
            "input",
        )
        self.assert_in("x input/x/a/foo_a", output)
        self.assert_in("A input/x/b/foo_b", output)
        self.assert_in("A input/y/foo_y", output)

    def test_create_pattern_exclude_folder_no_recurse(self):
        """test when patterns exclude a parent folder and, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/b\n! input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        self.create_regular_file("y/foo_y", size=1024 * 80)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "-v",
            "--list",
            "--patterns-from=" + self.patterns_file_path2,
            "test",
            "input",
        )
        self.assert_not_in("input/x/a/foo_a", output)
        self.assert_not_in("input/x/a", output)
        self.assert_in("A input/y/foo_y", output)

    def test_create_pattern_intermediate_folders_first(self):
        """test that intermediate folders appear first when patterns exclude a parent folder but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, "patterns2")
        with open(self.patterns_file_path2, "wb") as fd:
            fd.write(b"+ input/x/a\n+ input/x/b\n- input/x*\n")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        self.create_regular_file("x/a/foo_a", size=1024 * 80)
        self.create_regular_file("x/b/foo_b", size=1024 * 80)
        with changedir("input"):
            self.cmd(
                f"--repo={self.repository_location}",
                "create",
                "--patterns-from=" + self.patterns_file_path2,
                "test",
                ".",
            )

        # list the archive and verify that the "intermediate" folders appear before
        # their contents
        out = self.cmd(f"--repo={self.repository_location}", "list", "test", "--format", "{type} {path}{NL}")
        out_list = out.splitlines()

        self.assert_in("d x/a", out_list)
        self.assert_in("d x/b", out_list)

        assert out_list.index("d x/a") < out_list.index("- x/a/foo_a")
        assert out_list.index("d x/b") < out_list.index("- x/b/foo_b")

    def test_create_no_cache_sync(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        create_json = json.loads(
            self.cmd(
                f"--repo={self.repository_location}", "create", "--no-cache-sync", "--json", "--error", "test", "input"
            )
        )  # ignore experimental warning
        info_json = json.loads(self.cmd(f"--repo={self.repository_location}", "info", "-a", "test", "--json"))
        create_stats = create_json["cache"]["stats"]
        info_stats = info_json["cache"]["stats"]
        assert create_stats == info_stats
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        self.cmd(f"--repo={self.repository_location}", "create", "--no-cache-sync", "test2", "input")
        self.cmd(f"--repo={self.repository_location}", "rinfo")
        self.cmd(f"--repo={self.repository_location}", "check")

    def test_create_archivename_with_placeholder(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        ts = "1999-12-31T23:59:59"
        name_given = "test-{now}"  # placeholder in archive name gets replaced by borg
        name_expected = f"test-{ts}"  # placeholder in f-string gets replaced by python
        self.cmd(f"--repo={self.repository_location}", "create", f"--timestamp={ts}", name_given, "input")
        list_output = self.cmd(f"--repo={self.repository_location}", "rlist", "--short")
        assert name_expected in list_output

    def test_exclude_caches(self):
        self._create_test_caches()
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "--exclude-caches")
        self._assert_test_caches()

    def test_exclude_tagged(self):
        self._create_test_tagged()
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "input",
            "--exclude-if-present",
            ".NOBACKUP",
            "--exclude-if-present",
            "00-NOBACKUP",
        )
        self._assert_test_tagged()

    def test_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test",
            "input",
            "--exclude-if-present",
            ".NOBACKUP1",
            "--exclude-if-present",
            ".NOBACKUP2",
            "--exclude-caches",
            "--keep-exclude-tags",
        )
        self._assert_test_keep_tagged()

    def test_path_normalization(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir1/dir2/file", size=1024 * 80)
        with changedir("input/dir1/dir2"):
            self.cmd(f"--repo={self.repository_location}", "create", "test", "../../../input/dir1/../dir1/dir2/..")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test")
        self.assert_not_in("..", output)
        self.assert_in(" input/dir1/dir2/file", output)

    def test_exclude_normalization(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        with changedir("input"):
            self.cmd(f"--repo={self.repository_location}", "create", "test1", ".", "--exclude=file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test1")
        self.assert_equal(sorted(os.listdir("output")), ["file2"])
        with changedir("input"):
            self.cmd(f"--repo={self.repository_location}", "create", "test2", ".", "--exclude=./file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test2")
        self.assert_equal(sorted(os.listdir("output")), ["file2"])
        self.cmd(f"--repo={self.repository_location}", "create", "test3", "input", "--exclude=input/./file1")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test3")
        self.assert_equal(sorted(os.listdir("output/input")), ["file2"])

    def test_repeated_files(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input", "input")

    @pytest.mark.skipif("BORG_TESTS_IGNORE_MODES" in os.environ, reason="modes unreliable")
    @pytest.mark.skipif(is_win32, reason="modes unavailable on Windows")
    def test_umask(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        mode = os.stat(self.repository_path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_create_dry_run(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--dry-run", "test", "input")
        # Make sure no archive has been created
        with Repository(self.repository_path) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        self.assert_equal(len(manifest.archives), 0)

    def test_progress_on(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test4", "input", "--progress")
        self.assert_in("\r", output)

    def test_progress_off(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "test5", "input")
        self.assert_not_in("\r", output)

    def test_file_status(self):
        """test that various file status show expected results

        clearly incomplete: only tests for the weird "unchanged" status for now"""
        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "test", "input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        # should find first file as unmodified
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "test2", "input")
        self.assert_in("U input/file1", output)
        # this is expected, although surprising, for why, see:
        # https://borgbackup.readthedocs.org/en/latest/faq.html#i-am-seeing-a-added-status-for-a-unchanged-file
        self.assert_in("A input/file2", output)

    def test_file_status_cs_cache_mode(self):
        """test that a changed file with faked "previous" mtime still gets backed up in ctime,size cache_mode"""
        self.create_regular_file("file1", contents=b"123")
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "test1", "input", "--list", "--files-cache=ctime,size"
        )
        # modify file1, but cheat with the mtime (and atime) and also keep same size:
        st = os.stat("input/file1")
        self.create_regular_file("file1", contents=b"321")
        os.utime("input/file1", ns=(st.st_atime_ns, st.st_mtime_ns))
        # this mode uses ctime for change detection, so it should find file1 as modified
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "test2", "input", "--list", "--files-cache=ctime,size"
        )
        self.assert_in("M input/file1", output)

    def test_file_status_ms_cache_mode(self):
        """test that a chmod'ed file with no content changes does not get chunked again in mtime,size cache_mode"""
        self.create_regular_file("file1", size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=mtime,size", "test1", "input"
        )
        # change mode of file1, no content change:
        st = os.stat("input/file1")
        os.chmod("input/file1", st.st_mode ^ stat.S_IRWXO)  # this triggers a ctime change, but mtime is unchanged
        # this mode uses mtime for change detection, so it should find file1 as unmodified
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=mtime,size", "test2", "input"
        )
        self.assert_in("U input/file1", output)

    def test_file_status_rc_cache_mode(self):
        """test that files get rechunked unconditionally in rechunk,ctime cache mode"""
        self.create_regular_file("file1", size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=10)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=rechunk,ctime", "test1", "input"
        )
        # no changes here, but this mode rechunks unconditionally
        output = self.cmd(
            f"--repo={self.repository_location}", "create", "--list", "--files-cache=rechunk,ctime", "test2", "input"
        )
        self.assert_in("A input/file1", output)

    def test_file_status_excluded(self):
        """test that excluded paths are listed"""

        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        if has_lchflags:
            self.create_regular_file("file3", size=1024 * 80)
            platform.set_flags(os.path.join(self.input_path, "file3"), stat.UF_NODUMP)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        output = self.cmd(f"--repo={self.repository_location}", "create", "--list", "--exclude-nodump", "test", "input")
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)
        # should find second file as excluded
        output = self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "test1",
            "input",
            "--list",
            "--exclude-nodump",
            "--exclude",
            "*/file2",
        )
        self.assert_in("U input/file1", output)
        self.assert_in("x input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)

    def test_file_status_counters(self):
        """Test file status counters in the stats of `borg create --stats`"""

        def to_dict(borg_create_output):
            borg_create_output = borg_create_output.strip().splitlines()
            borg_create_output = [line.split(":", 1) for line in borg_create_output]
            borg_create_output = {
                key: int(value)
                for key, value in borg_create_output
                if key in ("Added files", "Unchanged files", "Modified files")
            }
            return borg_create_output

        # Test case set up: create a repository
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # Archive an empty dir
        result = self.cmd(f"--repo={self.repository_location}", "create", "--stats", "test_archive", self.input_path)
        result = to_dict(result)
        assert result["Added files"] == 0
        assert result["Unchanged files"] == 0
        assert result["Modified files"] == 0
        # Archive a dir with two added files
        self.create_regular_file("testfile1", contents=b"test1")
        time.sleep(0.01)  # testfile2 must have newer timestamps than testfile1
        self.create_regular_file("testfile2", contents=b"test2")
        result = self.cmd(f"--repo={self.repository_location}", "create", "--stats", "test_archive2", self.input_path)
        result = to_dict(result)
        assert result["Added files"] == 2
        assert result["Unchanged files"] == 0
        assert result["Modified files"] == 0
        # Archive a dir with 1 unmodified file and 1 modified
        self.create_regular_file("testfile1", contents=b"new data")
        result = self.cmd(f"--repo={self.repository_location}", "create", "--stats", "test_archive3", self.input_path)
        result = to_dict(result)
        # Should process testfile2 as added because of
        # https://borgbackup.readthedocs.io/en/stable/faq.html#i-am-seeing-a-added-status-for-an-unchanged-file
        assert result["Added files"] == 1
        assert result["Unchanged files"] == 0
        assert result["Modified files"] == 1

    def test_create_json(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        create_info = json.loads(self.cmd(f"--repo={self.repository_location}", "create", "--json", "test", "input"))
        # The usual keys
        assert "encryption" in create_info
        assert "repository" in create_info
        assert "cache" in create_info
        assert "last_modified" in create_info["repository"]

        archive = create_info["archive"]
        assert archive["name"] == "test"
        assert isinstance(archive["command_line"], list)
        assert isinstance(archive["duration"], float)
        assert len(archive["id"]) == 64
        assert "stats" in archive

    def test_create_topical(self):
        self.create_regular_file("file1", size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file("file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # no listing by default
        output = self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.assert_not_in("file1", output)
        # shouldn't be listed even if unchanged
        output = self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")
        self.assert_not_in("file1", output)
        # should list the file as unchanged
        output = self.cmd(f"--repo={self.repository_location}", "create", "test1", "input", "--list", "--filter=U")
        self.assert_in("file1", output)
        # should *not* list the file as changed
        output = self.cmd(f"--repo={self.repository_location}", "create", "test2", "input", "--list", "--filter=AM")
        self.assert_not_in("file1", output)
        # change the file
        self.create_regular_file("file1", size=1024 * 100)
        # should list the file as changed
        output = self.cmd(f"--repo={self.repository_location}", "create", "test3", "input", "--list", "--filter=AM")
        self.assert_in("file1", output)

    @pytest.mark.skipif(not are_fifos_supported() or is_cygwin, reason="FIFOs not supported, hangs on cygwin")
    def test_create_read_special_symlink(self):
        from threading import Thread

        def fifo_feeder(fifo_fn, data):
            fd = os.open(fifo_fn, os.O_WRONLY)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        data = b"foobar" * 1000

        fifo_fn = os.path.join(self.input_path, "fifo")
        link_fn = os.path.join(self.input_path, "link_fifo")
        os.mkfifo(fifo_fn)
        os.symlink(fifo_fn, link_fn)

        t = Thread(target=fifo_feeder, args=(fifo_fn, data))
        t.start()
        try:
            self.cmd(f"--repo={self.repository_location}", "create", "--read-special", "test", "input/link_fifo")
        finally:
            t.join()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            fifo_fn = "input/link_fifo"
            with open(fifo_fn, "rb") as f:
                extracted_data = f.read()
        assert extracted_data == data

    def test_create_read_special_broken_symlink(self):
        os.symlink("somewhere does not exist", os.path.join(self.input_path, "link"))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--read-special", "test", "input")
        output = self.cmd(f"--repo={self.repository_location}", "list", "test")
        assert "input/link -> somewhere does not exist" in output

    def test_log_json(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        log = self.cmd(
            f"--repo={self.repository_location}", "create", "test", "input", "--log-json", "--list", "--debug"
        )
        messages = {}  # type -> message, one of each kind
        for line in log.splitlines():
            msg = json.loads(line)
            messages[msg["type"]] = msg

        file_status = messages["file_status"]
        assert "status" in file_status
        assert file_status["path"].startswith("input")

        log_message = messages["log_message"]
        assert isinstance(log_message["time"], float)
        assert log_message["levelname"] == "DEBUG"  # there should only be DEBUG messages
        assert isinstance(log_message["message"], str)

    def test_common_options(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        log = self.cmd(f"--repo={self.repository_location}", "--debug", "create", "test", "input")
        assert "security: read previous location" in log

    def test_hashing_time(self):
        def extract_hashing_time(borg_create_output):
            borg_create_output = borg_create_output.strip().splitlines()
            borg_create_output = [line.split(":", 1) for line in borg_create_output]
            hashing_time = [line for line in borg_create_output if line[0] == "Time spent in hashing"].pop()
            hashing_time = hashing_time[1]
            hashing_time = float(hashing_time.removesuffix(" seconds"))
            return hashing_time

        # Test case set up: create a repository and a file
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self.create_regular_file("testfile", contents=randbytes(15000000))  # more data might be needed for faster CPUs
        # Archive
        result = self.cmd(f"--repo={self.repository_location}", "create", "--stats", "test_archive", self.input_path)
        hashing_time = extract_hashing_time(result)

        assert hashing_time > 0.0

    def test_chunking_time(self):
        def extract_chunking_time(borg_create_output):
            borg_create_output = borg_create_output.strip().splitlines()
            borg_create_output = [line.split(":", 1) for line in borg_create_output]
            chunking_time = [line for line in borg_create_output if line[0] == "Time spent in chunking"].pop()
            chunking_time = chunking_time[1]
            chunking_time = float(chunking_time.removesuffix(" seconds"))
            return chunking_time

        # Test case set up: create a repository and a file
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("testfile", contents=randbytes(10000000))
        # Archive
        result = self.cmd(f"--repo={self.repository_location}", "create", "--stats", "test_archive", self.input_path)
        chunking_time = extract_chunking_time(result)

        assert chunking_time > 0.0


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""

    @unittest.skip("test_basic_functionality seems incompatible with fakeroot and/or the binary.")
    def test_basic_functionality(self):
        pass
