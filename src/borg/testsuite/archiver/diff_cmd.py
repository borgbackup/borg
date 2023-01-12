import json
import os
import stat
import unittest

from ...constants import *  # NOQA
from .. import are_symlinks_supported, are_hardlinks_supported
from ..platform import is_win32
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_basic_functionality(self):
        # Setup files for the first snapshot
        self.create_regular_file("empty", size=0)
        self.create_regular_file("file_unchanged", size=128)
        self.create_regular_file("file_removed", size=256)
        self.create_regular_file("file_removed2", size=512)
        self.create_regular_file("file_replaced", size=1024)
        os.mkdir("input/dir_replaced_with_file")
        os.chmod("input/dir_replaced_with_file", stat.S_IFDIR | 0o755)
        os.mkdir("input/dir_removed")
        if are_symlinks_supported():
            os.mkdir("input/dir_replaced_with_link")
            os.symlink("input/dir_replaced_with_file", "input/link_changed")
            os.symlink("input/file_unchanged", "input/link_removed")
            os.symlink("input/file_removed2", "input/link_target_removed")
            os.symlink("input/empty", "input/link_target_contents_changed")
            os.symlink("input/empty", "input/link_replaced_by_file")
        if are_hardlinks_supported():
            os.link("input/file_replaced", "input/hardlink_target_replaced")
            os.link("input/empty", "input/hardlink_contents_changed")
            os.link("input/file_removed", "input/hardlink_removed")
            os.link("input/file_removed2", "input/hardlink_target_removed")

        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        # Create the first snapshot
        self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")

        # Setup files for the second snapshot
        self.create_regular_file("file_added", size=2048)
        self.create_regular_file("file_empty_added", size=0)
        os.unlink("input/file_replaced")
        self.create_regular_file("file_replaced", contents=b"0" * 4096)
        os.unlink("input/file_removed")
        os.unlink("input/file_removed2")
        os.rmdir("input/dir_replaced_with_file")
        self.create_regular_file("dir_replaced_with_file", size=8192)
        os.chmod("input/dir_replaced_with_file", stat.S_IFREG | 0o755)
        os.mkdir("input/dir_added")
        os.rmdir("input/dir_removed")
        if are_symlinks_supported():
            os.rmdir("input/dir_replaced_with_link")
            os.symlink("input/dir_added", "input/dir_replaced_with_link")
            os.unlink("input/link_changed")
            os.symlink("input/dir_added", "input/link_changed")
            os.symlink("input/dir_added", "input/link_added")
            os.unlink("input/link_replaced_by_file")
            self.create_regular_file("link_replaced_by_file", size=16384)
            os.unlink("input/link_removed")
        if are_hardlinks_supported():
            os.unlink("input/hardlink_removed")
            os.link("input/file_added", "input/hardlink_added")

        with open("input/empty", "ab") as fd:
            fd.write(b"appended_data")

        # Create the second snapshot
        self.cmd(f"--repo={self.repository_location}", "create", "test1a", "input")
        self.cmd(f"--repo={self.repository_location}", "create", "test1b", "input", "--chunker-params", "16,18,17,4095")

        def do_asserts(output, can_compare_ids):
            # File contents changed (deleted and replaced with a new file)
            change = "B" if can_compare_ids else "{:<19}".format("modified")
            assert "file_replaced" in output  # added to debug #3494
            assert f"{change} input/file_replaced" in output

            # File unchanged
            assert "input/file_unchanged" not in output

            # Directory replaced with a regular file
            if "BORG_TESTS_IGNORE_MODES" not in os.environ and not is_win32:
                assert "[drwxr-xr-x -> -rwxr-xr-x] input/dir_replaced_with_file" in output

            # Basic directory cases
            assert "added directory     input/dir_added" in output
            assert "removed directory   input/dir_removed" in output

            if are_symlinks_supported():
                # Basic symlink cases
                assert "changed link        input/link_changed" in output
                assert "added link          input/link_added" in output
                assert "removed link        input/link_removed" in output

                # Symlink replacing or being replaced
                assert "] input/dir_replaced_with_link" in output
                assert "] input/link_replaced_by_file" in output

                # Symlink target removed. Should not affect the symlink at all.
                assert "input/link_target_removed" not in output

            # The inode has two links and the file contents changed. Borg
            # should notice the changes in both links. However, the symlink
            # pointing to the file is not changed.
            change = "0 B" if can_compare_ids else "{:<19}".format("modified")
            assert f"{change} input/empty" in output
            if are_hardlinks_supported():
                assert f"{change} input/hardlink_contents_changed" in output
            if are_symlinks_supported():
                assert "input/link_target_contents_changed" not in output

            # Added a new file and a hard link to it. Both links to the same
            # inode should appear as separate files.
            assert "added       2.05 kB input/file_added" in output
            if are_hardlinks_supported():
                assert "added       2.05 kB input/hardlink_added" in output

            # check if a diff between nonexistent and empty new file is found
            assert "added           0 B input/file_empty_added" in output

            # The inode has two links and both of them are deleted. They should
            # appear as two deleted files.
            assert "removed       256 B input/file_removed" in output
            if are_hardlinks_supported():
                assert "removed       256 B input/hardlink_removed" in output

            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should not change this link at all.
            if are_hardlinks_supported():
                assert "input/hardlink_target_removed" not in output

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should not
            # change this link at all.
            if are_hardlinks_supported():
                assert "input/hardlink_target_replaced" not in output

        def do_json_asserts(output, can_compare_ids):
            def get_changes(filename, data):
                chgsets = [j["changes"] for j in data if j["path"] == filename]
                assert len(chgsets) < 2
                # return a flattened list of changes for given filename
                return [chg for chgset in chgsets for chg in chgset]

            # convert output to list of dicts
            joutput = [json.loads(line) for line in output.split("\n") if line]

            # File contents changed (deleted and replaced with a new file)
            expected = {"type": "modified", "added": 4096, "removed": 1024} if can_compare_ids else {"type": "modified"}
            assert expected in get_changes("input/file_replaced", joutput)

            # File unchanged
            assert not any(get_changes("input/file_unchanged", joutput))

            # Directory replaced with a regular file
            if "BORG_TESTS_IGNORE_MODES" not in os.environ and not is_win32:
                assert {"type": "mode", "old_mode": "drwxr-xr-x", "new_mode": "-rwxr-xr-x"} in get_changes(
                    "input/dir_replaced_with_file", joutput
                )

            # Basic directory cases
            assert {"type": "added directory"} in get_changes("input/dir_added", joutput)
            assert {"type": "removed directory"} in get_changes("input/dir_removed", joutput)

            if are_symlinks_supported():
                # Basic symlink cases
                assert {"type": "changed link"} in get_changes("input/link_changed", joutput)
                assert {"type": "added link"} in get_changes("input/link_added", joutput)
                assert {"type": "removed link"} in get_changes("input/link_removed", joutput)

                # Symlink replacing or being replaced
                assert any(
                    chg["type"] == "mode" and chg["new_mode"].startswith("l")
                    for chg in get_changes("input/dir_replaced_with_link", joutput)
                )
                assert any(
                    chg["type"] == "mode" and chg["old_mode"].startswith("l")
                    for chg in get_changes("input/link_replaced_by_file", joutput)
                )

                # Symlink target removed. Should not affect the symlink at all.
                assert not any(get_changes("input/link_target_removed", joutput))

            # The inode has two links and the file contents changed. Borg
            # should notice the changes in both links. However, the symlink
            # pointing to the file is not changed.
            expected = {"type": "modified", "added": 13, "removed": 0} if can_compare_ids else {"type": "modified"}
            assert expected in get_changes("input/empty", joutput)
            if are_hardlinks_supported():
                assert expected in get_changes("input/hardlink_contents_changed", joutput)
            if are_symlinks_supported():
                assert not any(get_changes("input/link_target_contents_changed", joutput))

            # Added a new file and a hard link to it. Both links to the same
            # inode should appear as separate files.
            assert {"type": "added", "size": 2048} in get_changes("input/file_added", joutput)
            if are_hardlinks_supported():
                assert {"type": "added", "size": 2048} in get_changes("input/hardlink_added", joutput)

            # check if a diff between nonexistent and empty new file is found
            assert {"type": "added", "size": 0} in get_changes("input/file_empty_added", joutput)

            # The inode has two links and both of them are deleted. They should
            # appear as two deleted files.
            assert {"type": "removed", "size": 256} in get_changes("input/file_removed", joutput)
            if are_hardlinks_supported():
                assert {"type": "removed", "size": 256} in get_changes("input/hardlink_removed", joutput)

            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should not change this link at all.
            if are_hardlinks_supported():
                assert not any(get_changes("input/hardlink_target_removed", joutput))

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should not
            # change this link at all.
            if are_hardlinks_supported():
                assert not any(get_changes("input/hardlink_target_replaced", joutput))

        do_asserts(self.cmd(f"--repo={self.repository_location}", "diff", "test0", "test1a"), True)
        # We expect exit_code=1 due to the chunker params warning
        do_asserts(self.cmd(f"--repo={self.repository_location}", "diff", "test0", "test1b", exit_code=1), False)
        do_json_asserts(self.cmd(f"--repo={self.repository_location}", "diff", "test0", "test1a", "--json-lines"), True)

    def test_sort_option(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

        self.create_regular_file("a_file_removed", size=8)
        self.create_regular_file("f_file_removed", size=16)
        self.create_regular_file("c_file_changed", size=32)
        self.create_regular_file("e_file_changed", size=64)
        self.cmd(f"--repo={self.repository_location}", "create", "test0", "input")

        os.unlink("input/a_file_removed")
        os.unlink("input/f_file_removed")
        os.unlink("input/c_file_changed")
        os.unlink("input/e_file_changed")
        self.create_regular_file("c_file_changed", size=512)
        self.create_regular_file("e_file_changed", size=1024)
        self.create_regular_file("b_file_added", size=128)
        self.create_regular_file("d_file_added", size=256)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", "input")

        output = self.cmd(f"--repo={self.repository_location}", "diff", "test0", "test1", "--sort")
        expected = [
            "a_file_removed",
            "b_file_added",
            "c_file_changed",
            "d_file_added",
            "e_file_changed",
            "f_file_removed",
        ]

        assert all(x in line for x, line in zip(expected, output.splitlines()))


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""
