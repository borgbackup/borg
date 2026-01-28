import json
import os
from pathlib import Path
import stat
import time
import pytest

from ...constants import *  # NOQA
from .. import are_symlinks_supported, are_hardlinks_supported, granularity_sleep
from ...platformflags import is_win32, is_freebsd, is_netbsd
from . import (
    cmd,
    create_regular_file,
    RK_ENCRYPTION,
    assert_line_exists,
    generate_archiver_tests,
    assert_line_not_exists,
)

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_basic_functionality(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # Setup files for the first snapshot
    create_regular_file(archiver.input_path, "empty", size=0)
    create_regular_file(archiver.input_path, "file_unchanged", size=128)
    create_regular_file(archiver.input_path, "file_removed", size=256)
    create_regular_file(archiver.input_path, "file_removed2", size=512)
    create_regular_file(archiver.input_path, "file_replaced", size=1024)
    create_regular_file(archiver.input_path, "file_touched", size=128)
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
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Create the first snapshot
    cmd(archiver, "create", "test0", "input")
    # Setup files for the second snapshot
    create_regular_file(archiver.input_path, "file_added", size=2048)
    create_regular_file(archiver.input_path, "file_empty_added", size=0)
    os.unlink("input/file_replaced")
    create_regular_file(archiver.input_path, "file_replaced", contents=b"0" * 4096)
    os.unlink("input/file_removed")
    os.unlink("input/file_removed2")
    granularity_sleep()
    Path("input/file_touched").touch()
    os.rmdir("input/dir_replaced_with_file")
    create_regular_file(archiver.input_path, "dir_replaced_with_file", size=8192)
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
        create_regular_file(archiver.input_path, "link_replaced_by_file", size=16384)
        os.unlink("input/link_removed")
    if are_hardlinks_supported():
        os.unlink("input/hardlink_removed")
        os.link("input/file_added", "input/hardlink_added")
    with open("input/empty", "ab") as fd:
        fd.write(b"appended_data")
    # Create the second snapshot
    cmd(archiver, "create", "test1a", "input")
    cmd(archiver, "create", "test1b", "input", "--chunker-params", "16,18,17,4095")

    def do_asserts(output, can_compare_ids, content_only=False):
        lines: list = output.splitlines()
        assert "file_replaced" in output  # added to debug #3494
        change = "modified.*B" if can_compare_ids else r"modified:  \(can't get size\)"
        assert_line_exists(lines, f"{change}.*input/file_replaced")
        # File unchanged
        assert "input/file_unchanged" not in output

        # Directory replaced with a regular file
        if "BORG_TESTS_IGNORE_MODES" not in os.environ and not is_win32 and not content_only:
            assert_line_exists(lines, "[drwxr-xr-x -> -rwxr-xr-x].*input/dir_replaced_with_file")

        # Basic directory cases
        assert "added directory             input/dir_added" in output
        assert "removed directory           input/dir_removed" in output

        if are_symlinks_supported():
            # Basic symlink cases
            assert_line_exists(lines, "changed link.*input/link_changed")
            assert_line_exists(lines, "added link.*input/link_added")
            assert_line_exists(lines, "removed link.*input/link_removed")

            # Symlink replacing or being replaced
            if not content_only:
                assert "input/dir_replaced_with_link" in output
                assert "input/link_replaced_by_file" in output

            # Symlink target removed. Should not affect the symlink at all.
            assert "input/link_target_removed" not in output

        # The inode has two links and the file contents changed. Borg
        # should notice the changes in both links. However, the symlink
        # pointing to the file is not changed.
        change = "modified.*0 B" if can_compare_ids else r"modified:  \(can't get size\)"
        assert_line_exists(lines, f"{change}.*input/empty")

        # Do not show a 0 byte change for a file whose contents weren't modified.
        assert_line_not_exists(lines, "0 B.*input/file_touched")
        if not content_only:
            assert_line_exists(lines, "[cm]time:.*input/file_touched")
        else:
            # And if we're doing content-only, don't show the file at all.
            assert "input/file_touched" not in output

        if are_hardlinks_supported():
            assert_line_exists(lines, f"{change}.*input/hardlink_contents_changed")
        if are_symlinks_supported():
            assert "input/link_target_contents_changed" not in output

        # Added a new file and a hard link to it. Both links to the same
        # inode should appear as separate files.
        assert "added:              2.05 kB input/file_added" in output
        if are_hardlinks_supported():
            assert "added:              2.05 kB input/hardlink_added" in output

        # check if a diff between nonexistent and empty new file is found
        assert "added:                  0 B input/file_empty_added" in output

        # The inode has two links and both of them are deleted. They should
        # appear as two deleted files.
        assert "removed:              256 B input/file_removed" in output
        if are_hardlinks_supported():
            assert "removed:              256 B input/hardlink_removed" in output

        if are_hardlinks_supported() and content_only:
            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should only change the ctime since removing
            # the link would result in the decrementation of the inode's hard-link count.
            assert "input/hardlink_target_removed" not in output

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should only change
            # its ctime. This should not be reflected in the output if content-only is set
            assert "input/hardlink_target_replaced" not in output

    def do_json_asserts(output, can_compare_ids, content_only=False):
        def get_changes(filename, data):
            chgsets = [j["changes"] for j in data if j["path"] == filename]
            assert len(chgsets) < 2
            # return a flattened list of changes for given filename
            return sum(chgsets, [])

        # convert output to list of dicts
        joutput = [json.loads(line) for line in output.split("\n") if line]

        # File contents changed (deleted and replaced with a new file)
        expected = {"type": "modified", "added": 4096, "removed": 1024} if can_compare_ids else {"type": "modified"}
        assert expected in get_changes("input/file_replaced", joutput)

        # File unchanged
        assert not any(get_changes("input/file_unchanged", joutput))

        # Do not show a 0 byte change for a file whose contents weren't modified.
        unexpected = {"type": "modified", "added": 0, "removed": 0}
        assert unexpected not in get_changes("input/file_touched", joutput)
        if not content_only:
            # on win32, ctime is the file creation time and does not change.
            # not sure why netbsd only has mtime, but it does, #8703.
            expected = {"mtime"} if (is_win32 or is_netbsd) else {"mtime", "ctime"}
            assert expected.issubset({c["type"] for c in get_changes("input/file_touched", joutput)})
        else:
            # And if we're doing content-only, don't show the file at all.
            assert not any(get_changes("input/file_touched", joutput))

        # Directory replaced with a regular file
        if "BORG_TESTS_IGNORE_MODES" not in os.environ and not is_win32 and not content_only:
            assert {"type": "changed mode", "item1": "drwxr-xr-x", "item2": "-rwxr-xr-x"} in get_changes(
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

            if not content_only:
                assert any(
                    chg["type"] == "changed mode" and chg["item1"].startswith("d") and chg["item2"].startswith("l")
                    for chg in get_changes("input/dir_replaced_with_link", joutput)
                ), get_changes("input/dir_replaced_with_link", joutput)
                assert any(
                    chg["type"] == "changed mode" and chg["item1"].startswith("l") and chg["item2"].startswith("-")
                    for chg in get_changes("input/link_replaced_by_file", joutput)
                ), get_changes("input/link_replaced_by_file", joutput)

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
        assert {"added": 2048, "removed": 0, "type": "added"} in get_changes("input/file_added", joutput)
        if are_hardlinks_supported():
            assert {"added": 2048, "removed": 0, "type": "added"} in get_changes("input/hardlink_added", joutput)

        # check if a diff between nonexistent and empty new file is found
        assert {"added": 0, "removed": 0, "type": "added"} in get_changes("input/file_empty_added", joutput)

        # The inode has two links and both of them are deleted. They should
        # appear as two deleted files.
        assert {"added": 0, "removed": 256, "type": "removed"} in get_changes("input/file_removed", joutput)
        if are_hardlinks_supported():
            assert {"added": 0, "removed": 256, "type": "removed"} in get_changes("input/hardlink_removed", joutput)

        if are_hardlinks_supported() and content_only:
            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should only change the ctime since removing
            # the link would result in the decrementation of the inode's hard-link count.
            assert not any(get_changes("input/hardlink_target_removed", joutput))

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should only change
            # its ctime. This should not be reflected in the output if content-only is set
            assert not any(get_changes("input/hardlink_target_replaced", joutput))

    output = cmd(archiver, "diff", "test0", "test1a")
    do_asserts(output, True)

    output = cmd(archiver, "diff", "test0", "test1b", "--content-only")
    do_asserts(output, False, content_only=True)

    output = cmd(archiver, "diff", "test0", "test1a", "--json-lines")
    do_json_asserts(output, True)

    output = cmd(archiver, "diff", "test0", "test1a", "--json-lines", "--content-only")
    do_json_asserts(output, True, content_only=True)


def test_time_diffs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "test_file", size=10)
    cmd(archiver, "create", "archive1", "input")
    time.sleep(0.1)
    os.unlink("input/test_file")
    granularity_sleep(ctime_quirk=True)
    create_regular_file(archiver.input_path, "test_file", size=15)
    cmd(archiver, "create", "archive2", "input")
    output = cmd(archiver, "diff", "archive1", "archive2", "--format", "'{mtime}{ctime} {path}{NL}'")
    assert "mtime" in output
    assert "ctime" in output  # Should show up on Windows as well since it is a new file.

    granularity_sleep()
    os.chmod("input/test_file", 0o777)
    cmd(archiver, "create", "archive3", "input")
    output = cmd(archiver, "diff", "archive2", "archive3", "--format", "'{mtime}{ctime} {path}{NL}'")
    assert "mtime" not in output
    # Checking platform because ctime should not be shown on Windows since it wasn't recreated.
    if not is_win32:
        assert "ctime" in output
    else:
        assert "ctime" not in output


def test_sort_by_option(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    create_regular_file(archiver.input_path, "a_file_removed", size=8)
    create_regular_file(archiver.input_path, "f_file_removed", size=16)
    create_regular_file(archiver.input_path, "c_file_changed", size=32)
    create_regular_file(archiver.input_path, "e_file_changed", size=64)
    cmd(archiver, "create", "test0", "input")

    os.unlink("input/a_file_removed")
    os.unlink("input/f_file_removed")
    os.unlink("input/c_file_changed")
    os.unlink("input/e_file_changed")
    create_regular_file(archiver.input_path, "c_file_changed", size=512)
    create_regular_file(archiver.input_path, "e_file_changed", size=1024)
    create_regular_file(archiver.input_path, "b_file_added", size=128)
    create_regular_file(archiver.input_path, "d_file_added", size=256)
    cmd(archiver, "create", "test1", "input")

    output = cmd(archiver, "diff", "test0", "test1", "--sort-by=path", "--content-only")
    expected = ["a_file_removed", "b_file_added", "c_file_changed", "d_file_added", "e_file_changed", "f_file_removed"]
    assert isinstance(output, str)
    outputs = output.splitlines()
    assert len(outputs) == len(expected)
    assert all(x in line for x, line in zip(expected, outputs))


def test_sort_by_invalid_field_is_rejected(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    create_regular_file(archiver.input_path, "file", size=1)
    cmd(archiver, "create", "a1", "input")
    create_regular_file(archiver.input_path, "file", size=2)
    cmd(archiver, "create", "a2", "input")

    # Unsupported field should cause argument parsing error
    cmd(archiver, "diff", "a1", "a2", "--sort-by=not_a_field", exit_code=EXIT_ERROR)


def test_sort_by_size_added_then_path(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Base archive with two files that will be removed later
    create_regular_file(archiver.input_path, "r_big_removed", size=50)
    create_regular_file(archiver.input_path, "r_small_removed", size=5)
    cmd(archiver, "create", "base", "input")

    # Second archive: remove both above and add two new files of different sizes
    os.unlink("input/r_big_removed")
    os.unlink("input/r_small_removed")
    create_regular_file(archiver.input_path, "a_small_added", size=10)
    create_regular_file(archiver.input_path, "b_large_added", size=30)
    cmd(archiver, "create", "next", "input")

    # Sort by size added (ascending), then path to break ties deterministically
    output = cmd(archiver, "diff", "base", "next", "--sort-by=size_added,path", "--content-only")
    lines = output.splitlines()
    # Expect removed entries first (size_added=0), ordered by path, then added entries by increasing size
    expected_order = [
        "removed:.*input/r_big_removed",  # size_added=0
        "removed:.*input/r_small_removed",  # size_added=0
        "added:.*10 B.*input/a_small_added",
        "added:.*30 B.*input/b_large_added",
    ]
    assert len(lines) == len(expected_order)
    for pattern, line in zip(expected_order, lines):
        assert_line_exists([line], pattern)


@pytest.mark.parametrize(
    "sort_key",
    [
        "path",
        "size",
        "size_added",
        "size_removed",
        "size_diff",
        "user",
        "group",
        "uid",
        "gid",
        "ctime",
        "mtime",
        "ctime_diff",
        "mtime_diff",
    ],
)
def test_sort_by_all_keys_with_directions(archivers, request, sort_key):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Prepare initial files
    create_regular_file(archiver.input_path, "a_removed", size=11)
    create_regular_file(archiver.input_path, "f_removed", size=22)
    create_regular_file(archiver.input_path, "c_changed", size=33)
    create_regular_file(archiver.input_path, "e_changed", size=44)
    cmd(archiver, "create", "s0", "input")

    # Ensure that subsequent modifications happen on a later timestamp tick than s0
    granularity_sleep()

    # Create differences for second archive
    os.unlink("input/a_removed")
    os.unlink("input/f_removed")
    os.unlink("input/c_changed")
    os.unlink("input/e_changed")
    # Recreate changed files with different sizes
    create_regular_file(archiver.input_path, "c_changed", size=333)
    create_regular_file(archiver.input_path, "e_changed", size=444)
    # Added files
    create_regular_file(archiver.input_path, "b_added", size=55)
    create_regular_file(archiver.input_path, "d_added", size=66)
    cmd(archiver, "create", "s1", "input")

    expected_paths = {
        "input/a_removed",
        "input/b_added",
        "input/c_changed",
        "input/d_added",
        "input/e_changed",
        "input/f_removed",
    }

    # Exercise both ascending and descending for each key.
    for direction in ("<", ">"):
        sort_spec = f"{direction}{sort_key},path"
        output = cmd(archiver, "diff", "s0", "s1", f"--sort-by={sort_spec}", "--content-only")
        lines = output.splitlines()
        assert len(lines) == len(expected_paths)
        # Validate that we got exactly the expected items regardless of order.
        # As we do not test the order, this is mostly for test coverage.
        seen_paths = {line.split()[-1] for line in lines}
        assert seen_paths == expected_paths


@pytest.mark.skipif(
    not are_hardlinks_supported() or is_freebsd or is_netbsd or is_win32,
    reason="hardlinks not supported or test failing on freebsd, netbsd and windows",
)
def test_hard_link_deletion_and_replacement(archivers, request):
    archiver = request.getfixturevalue(archivers)

    # repo-create changes umask, so create the repo first to avoid any
    # unexpected permission changes.
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    path_a = os.path.join(archiver.input_path, "a")
    path_b = os.path.join(archiver.input_path, "b")
    os.mkdir(path_a)
    os.mkdir(path_b)
    hl_a = os.path.join(path_a, "hardlink")
    hl_b = os.path.join(path_b, "hardlink")
    create_regular_file(archiver.input_path, hl_a, contents=b"123456")
    os.link(hl_a, hl_b)

    cmd(archiver, "create", "test0", "input")
    os.unlink(hl_a)  # Don't duplicate warning message - one is enough.
    cmd(archiver, "create", "test1", "input")

    # Moral equivalent of test_multiple_link_exclusion in borg v1.x... see #8344
    # Borg v2 doesn't have this issue comparing hard-links, so we'll defer to
    # POSIX behavior:
    # https://pubs.opengroup.org/onlinepubs/9799919799/functions/unlink.html
    # Upon successful completion, unlink() shall mark for update the last data modification
    # and last file status change timestamps of the parent directory. Also, if the
    # file's link count is not 0, the last file status change timestamp of the
    # file shall be marked for update.
    output = cmd(
        archiver, "diff", "--pattern=+ fm:input/b", "--pattern=! **/", "test0", "test1", exit_code=EXIT_SUCCESS
    )
    lines = output.splitlines()
    # Directory was excluded.
    assert_line_not_exists(lines, "input/a$")
    # Remaining hardlink
    assert_line_exists(lines, "ctime:.*input/b/hardlink")
    assert_line_not_exists(lines, ".*mtime:.*input/b/hardlink")
    # Deleted hardlink was excluded
    assert_line_not_exists(lines, "input/a/hardlink$")

    # Now try again, except with no patterns!
    output = cmd(archiver, "diff", "test0", "test1", exit_code=EXIT_SUCCESS)
    lines = output.splitlines()
    # Directory... preferably, let's not care about order differences are presented.
    assert_line_exists(lines, "[cm]time:.*[cm]time:.*input/a")
    # Remaining hardlink
    assert_line_exists(lines, "ctime:.*input/b/hardlink")
    assert_line_not_exists(lines, ".*mtime:.*input/b/hardlink")
    # Deleted hardlink
    assert_line_exists(lines, "removed:.*input/a/hardlink")

    # Now recreate the unlinked file as a different entity with identical
    # contents.
    create_regular_file(archiver.input_path, hl_a, contents=b"123456")
    cmd(archiver, "create", "test2", "input")

    # Compare test0 and test2.
    output = cmd(archiver, "diff", "test0", "test2", exit_code=EXIT_SUCCESS)
    lines = output.splitlines()
    # Adding a file changes c/mtime.
    assert_line_exists(lines, "[cm]time:.*[cm]time:.*input/a$")
    # Different c/mtime but no apparent changes (i.e. perms) or content
    # modifications should be a hint that something hard-link related is going on.
    assert_line_exists(lines, "[cm]time:.*[cm]time:.*input/a/hardlink")
    assert_line_not_exists(lines, "modified.*B.*input/a/hardlink")
    assert_line_not_exists(lines, "-[r-][w-][x-].*input/a/hardlink")
    # ctime changed because the hard-link count went down. But no mtime changes
    # because file content isn't modified. No permissions changes either.
    # This is another hint that something hard-link related changed.
    assert_line_exists(lines, "ctime:.*input/b/hardlink")
    assert_line_not_exists(lines, ".*mtime:.*input/b/hardlink")
    assert_line_not_exists(lines, "modified.*B.*input/b/hardlink")
    assert_line_not_exists(lines, "-[r-][w-][x-].*input/b/hardlink")

    # Finally, compare test1 and test2.
    output = cmd(archiver, "diff", "test1", "test2", exit_code=EXIT_SUCCESS)
    lines = output.splitlines()
    # Same situation applies as previous diff for a.
    assert_line_exists(lines, "[cm]time:.*[cm]time:.*input/a$")
    # From test1 to test2's POV, the a/hardlink file is a fresh new file.
    assert_line_exists(lines, "added.*B.*input/a/hardlink")
    # But the b/hardlink file was not modified at all.
    assert_line_not_exists(lines, ".*input/b/hardlink")
