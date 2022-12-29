import errno
import os
import shutil
import unittest
from unittest.mock import patch

import pytest

from ... import xattr
from ...chunker import has_seek_hole
from ...constants import *  # NOQA
from ...helpers import EXIT_WARNING
from ...helpers import flags_noatime, flags_normal
from .. import changedir
from .. import are_symlinks_supported, are_hardlinks_supported, is_utime_fully_supported, is_birthtime_fully_supported
from ..platform import is_darwin
from . import (
    ArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RemoteArchiverTestCaseBase,
    RK_ENCRYPTION,
    requires_hardlinks,
    BORG_EXES,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    @pytest.mark.skipif(not are_symlinks_supported(), reason="symlinks not supported")
    def test_symlink_extract(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert os.readlink("input/link1") == "somewhere"

    @pytest.mark.skipif(
        not are_symlinks_supported() or not are_hardlinks_supported() or is_darwin,
        reason="symlinks or hardlinks or hardlinked symlinks not supported",
    )
    def test_hardlinked_symlinks_extract(self):
        self.create_regular_file("target", size=1024)
        with changedir("input"):
            os.symlink("target", "symlink1")
            os.link("symlink1", "symlink2", follow_symlinks=False)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test")
            print(output)
            with changedir("input"):
                assert os.path.exists("target")
                assert os.readlink("symlink1") == "target"
                assert os.readlink("symlink2") == "target"
                st1 = os.stat("symlink1", follow_symlinks=False)
                st2 = os.stat("symlink2", follow_symlinks=False)
                assert st1.st_nlink == 2
                assert st2.st_nlink == 2
                assert st1.st_ino == st2.st_ino
                assert st1.st_size == st2.st_size

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    def test_atime(self):
        def has_noatime(some_file):
            atime_before = os.stat(some_file).st_atime_ns
            try:
                with open(os.open(some_file, flags_noatime)) as file:
                    file.read()
            except PermissionError:
                return False
            else:
                atime_after = os.stat(some_file).st_atime_ns
                noatime_used = flags_noatime != flags_normal
                return noatime_used and atime_before == atime_after

        self.create_test_files()
        atime, mtime = 123456780, 234567890
        have_noatime = has_noatime("input/file1")
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "--atime", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9
        if have_noatime:
            assert sti.st_atime_ns == sto.st_atime_ns == atime * 1e9
        else:
            # it touched the input file's atime while backing it up
            assert sto.st_atime_ns == atime * 1e9

    @pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
    @pytest.mark.skipif(
        not is_birthtime_fully_supported(), reason="cannot properly setup and execute test without birthtime"
    )
    def test_birthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime("input/file1", (atime, birthtime))
        os.utime("input/file1", (atime, mtime))
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        sti = os.stat("input/file1")
        sto = os.stat("output/input/file1")
        assert int(sti.st_birthtime * 1e9) == int(sto.st_birthtime * 1e9) == birthtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

    def test_sparse_file(self):
        def is_sparse(fn, total_size, hole_size):
            st = os.stat(fn)
            assert st.st_size == total_size
            sparse = True
            if sparse and hasattr(st, "st_blocks") and st.st_blocks * 512 >= st.st_size:
                sparse = False
            if sparse and has_seek_hole:
                with open(fn, "rb") as fd:
                    # only check if the first hole is as expected, because the 2nd hole check
                    # is problematic on xfs due to its "dynamic speculative EOF preallocation
                    try:
                        if fd.seek(0, os.SEEK_HOLE) != 0:
                            sparse = False
                        if fd.seek(0, os.SEEK_DATA) != hole_size:
                            sparse = False
                    except OSError:
                        # OS/FS does not really support SEEK_HOLE/SEEK_DATA
                        sparse = False
            return sparse

        filename = os.path.join(self.input_path, "sparse")
        content = b"foobar"
        hole_size = 5 * (1 << CHUNK_MAX_EXP)  # 5 full chunker buffers
        total_size = hole_size + len(content) + hole_size
        with open(filename, "wb") as fd:
            # create a file that has a hole at the beginning and end (if the
            # OS and filesystem supports sparse files)
            fd.seek(hole_size, 1)
            fd.write(content)
            fd.seek(hole_size, 1)
            pos = fd.tell()
            fd.truncate(pos)
        # we first check if we could create a sparse input file:
        sparse_support = is_sparse(filename, total_size, hole_size)
        if sparse_support:
            # we could create a sparse input file, so creating a backup of it and
            # extracting it again (as sparse) should also work:
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
            self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
            with changedir(self.output_path):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--sparse")
            self.assert_dirs_equal("input", "output/input")
            filename = os.path.join(self.output_path, "input", "sparse")
            with open(filename, "rb") as fd:
                # check if file contents are as expected
                self.assert_equal(fd.read(hole_size), b"\0" * hole_size)
                self.assert_equal(fd.read(len(content)), content)
                self.assert_equal(fd.read(hole_size), b"\0" * hole_size)
            assert is_sparse(filename, total_size, hole_size)

    def test_unusual_filenames(self):
        filenames = ["normal", "with some blanks", "(with_parens)"]
        for filename in filenames:
            filename = os.path.join(self.input_path, filename)
            with open(filename, "wb"):
                pass
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        for filename in filenames:
            with changedir("output"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", os.path.join("input", filename))
            assert os.path.exists(os.path.join("output", "input", filename))

    def test_strip_components(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir/file")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "3")
            assert not os.path.exists("file")
            with self.assert_creates_file("file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "2")
            with self.assert_creates_file("dir/file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "1")
            with self.assert_creates_file("input/dir/file"):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "0")

    @requires_hardlinks
    def test_extract_hardlinks1(self):
        self._extract_hardlinks_setup()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert os.stat("input/source").st_nlink == 4
            assert os.stat("input/abba").st_nlink == 4
            assert os.stat("input/dir1/hardlink").st_nlink == 4
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 4
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"

    @requires_hardlinks
    def test_extract_hardlinks2(self):
        self._extract_hardlinks_setup()
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--strip-components", "2")
            assert os.stat("hardlink").st_nlink == 2
            assert os.stat("subdir/hardlink").st_nlink == 2
            assert open("subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("aaaa").st_nlink == 2
            assert os.stat("source2").st_nlink == 2
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "input/dir1")
            assert os.stat("input/dir1/hardlink").st_nlink == 2
            assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
            assert open("input/dir1/subdir/hardlink", "rb").read() == b"123456"
            assert os.stat("input/dir1/aaaa").st_nlink == 2
            assert os.stat("input/dir1/source2").st_nlink == 2

    @requires_hardlinks
    def test_extract_hardlinks_twice(self):
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
        # now test extraction
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            # if issue #5603 happens, extraction gives rc == 1 (triggering AssertionError) and warnings like:
            # input/a/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/a/hardlink'
            # input/b/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/b/hardlink'
            # otherwise, when fixed, the hardlinks should be there and have a link count of 2
            assert os.stat("input/a/hardlink").st_nlink == 2
            assert os.stat("input/b/hardlink").st_nlink == 2

    def test_extract_include_exclude(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude=input/file4", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "input/file1")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1"])
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--exclude=input/file2")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file3"])
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file3"])

    def test_extract_include_exclude_regex(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        # Create with regular expression exclusion for file4
        self.cmd(f"--repo={self.repository_location}", "create", "--exclude=re:input/file4$", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333"])
        shutil.rmtree("output/input")

        # Extract with regular expression exclusion
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--exclude=re:file3+")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Combine --exclude with fnmatch and regular expression
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--exclude=input/file2",
                "--exclude=re:file[01]",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file3", "file333"])
        shutil.rmtree("output/input")

        # Combine --exclude-from and regular expression exclusion
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--exclude-from=" + self.exclude_file_path,
                "--exclude=re:file1",
                "--exclude=re:file(\\d)\\1\\1$",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file3"])

    def test_extract_include_exclude_regex_from_file(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        # Create while excluding using mixed pattern styles
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:input/file4$\n")
            fd.write(b"fm:*file3*\n")

        self.cmd(
            f"--repo={self.repository_location}", "create", "--exclude-from=" + self.exclude_file_path, "test", "input"
        )
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Exclude using regular expression
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:file3+\n")

        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Mixed exclude pattern styles
        with open(self.exclude_file_path, "wb") as fd:
            fd.write(b"re:file(\\d)\\1\\1$\n")
            fd.write(b"fm:nothingwillmatchthis\n")
            fd.write(b"*/file1\n")
            fd.write(b"re:file2$\n")

        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--exclude-from=" + self.exclude_file_path
            )
        self.assert_equal(sorted(os.listdir("output/input")), [])

    def test_extract_with_pattern(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        # Extract everything with regular expression
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "re:.*")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333", "file4"])
        shutil.rmtree("output/input")

        # Extract with pattern while also excluding files
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "--exclude=re:file[34]$", "test", r"re:file\d$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Combine --exclude with pattern for extraction
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "--exclude=input/file1", "test", "re:file[12]$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file2"])
        shutil.rmtree("output/input")

        # Multiple pattern
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "fm:input/file1", "fm:*file33*", "input/file2"
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file333"])

    def test_extract_list_output(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file", size=1024 * 80)

        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_not_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--info")
        self.assert_not_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--list")
        self.assert_in("input/file", output)
        shutil.rmtree("output/input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--list", "--info")
        self.assert_in("input/file", output)

    def test_extract_progress(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

        with changedir("output"):
            output = self.cmd(f"--repo={self.repository_location}", "extract", "test", "--progress")
            assert "Extracting:" in output

    def test_extract_pattern_opt(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file_important", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(
                f"--repo={self.repository_location}",
                "extract",
                "test",
                "--pattern=+input/file_important",
                "--pattern=-input/file*",
            )
        self.assert_equal(sorted(os.listdir("output/input")), ["file_important"])

    @pytest.mark.skipif(not xattr.XATTR_FAKEROOT, reason="Linux capabilities test, requires fakeroot >= 1.20.2")
    def test_extract_capabilities(self):
        fchown = os.fchown

        # We need to patch chown manually to get the behaviour Linux has, since fakeroot does not
        # accurately model the interaction of chown(2) and Linux capabilities, i.e. it does not remove them.
        def patched_fchown(fd, uid, gid):
            xattr.setxattr(fd, b"security.capability", b"", follow_symlinks=False)
            fchown(fd, uid, gid)

        # The capability descriptor used here is valid and taken from a /usr/bin/ping
        capabilities = b"\x01\x00\x00\x02\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"security.capability", capabilities)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(os, "fchown", patched_fchown):
                self.cmd(f"--repo={self.repository_location}", "extract", "test")
            assert xattr.getxattr(b"input/file", b"security.capability") == capabilities

    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_extract_xattrs_errors(self):
        def patched_setxattr_E2BIG(*args, **kwargs):
            raise OSError(errno.E2BIG, "E2BIG")

        def patched_setxattr_ENOTSUP(*args, **kwargs):
            raise OSError(errno.ENOTSUP, "ENOTSUP")

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"user.attribute", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            input_abspath = os.path.abspath("input/file")
            with patch.object(xattr, "setxattr", patched_setxattr_E2BIG):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "too big for this filesystem" in out
                assert "when setting extended attribute user.attribute" in out
            os.remove(input_abspath)
            with patch.object(xattr, "setxattr", patched_setxattr_ENOTSUP):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "ENOTSUP" in out
                assert "when setting extended attribute user.attribute" in out
            os.remove(input_abspath)
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                out = self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)
                assert "EACCES" in out
                assert "when setting extended attribute user.attribute" in out
            assert os.path.isfile(input_abspath)

    @pytest.mark.skipif(not is_darwin, reason="only for macOS")
    def test_extract_xattrs_resourcefork(self):
        self.create_regular_file("file")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        input_path = os.path.abspath("input/file")
        xa_key, xa_value = b"com.apple.ResourceFork", b"whatshouldbehere"  # issue #7234
        xattr.setxattr(input_path.encode(), xa_key, xa_value)
        birthtime_expected = os.stat(input_path).st_birthtime
        mtime_expected = os.stat(input_path).st_mtime_ns
        # atime_expected = os.stat(input_path).st_atime_ns
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
            extracted_path = os.path.abspath("input/file")
            birthtime_extracted = os.stat(extracted_path).st_birthtime
            mtime_extracted = os.stat(extracted_path).st_mtime_ns
            # atime_extracted = os.stat(extracted_path).st_atime_ns
            xa_value_extracted = xattr.getxattr(extracted_path.encode(), xa_key)
        assert xa_value_extracted == xa_value
        assert birthtime_extracted == birthtime_expected
        assert mtime_extracted == mtime_expected
        # assert atime_extracted == atime_expected  # still broken, but not really important.

    def test_overwrite(self):
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("dir2/file2", size=1024 * 80)
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        # Overwriting regular files and directories should be supported
        os.mkdir("output/input")
        os.mkdir("output/input/file1")
        os.mkdir("output/input/dir2")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test")
        self.assert_dirs_equal("input", "output/input")
        # But non-empty dirs should fail
        os.unlink("output/input/file1")
        os.mkdir("output/input/file1")
        os.mkdir("output/input/file1/dir")
        with changedir("output"):
            self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=1)

    # derived from test_extract_xattrs_errors()
    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_do_not_fail_when_percent_is_in_xattr_name(self):
        """https://github.com/borgbackup/borg/issues/6063"""

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        self.create_regular_file("file")
        xattr.setxattr(b"input/file", b"user.attribute%p", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)

    # derived from test_extract_xattrs_errors()
    @pytest.mark.skipif(
        not xattr.XATTR_FAKEROOT, reason="xattr not supported on this system or on this version of fakeroot"
    )
    def test_do_not_fail_when_percent_is_in_file_name(self):
        """https://github.com/borgbackup/borg/issues/6063"""

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, "EACCES")

        os.makedirs(os.path.join(self.input_path, "dir%p"))
        xattr.setxattr(b"input/dir%p", b"user.attribute", b"value")
        self.cmd(f"--repo={self.repository_location}", "rcreate", "-e" "none")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with changedir("output"):
            with patch.object(xattr, "setxattr", patched_setxattr_EACCES):
                self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_WARNING)


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    @unittest.skip("patches objects")
    def test_extract_capabilities(self):
        pass

    @unittest.skip("patches objects")
    def test_extract_xattrs_errors(self):
        pass

    @unittest.skip("test_overwrite seems incompatible with fakeroot and/or the binary.")
    def test_overwrite(self):
        pass

    @unittest.skip("patches objects")
    def test_do_not_fail_when_percent_is_in_xattr_name(self):
        pass

    @unittest.skip("patches objects")
    def test_do_not_fail_when_percent_is_in_file_name(self):
        pass
