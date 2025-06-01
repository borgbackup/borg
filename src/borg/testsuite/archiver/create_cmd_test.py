import errno
import json
import os
import tempfile
import shutil
import socket
import stat
import subprocess
import time

import pytest

from ... import platform
from ...constants import *  # NOQA
from ...constants import zeros
from ...manifest import Manifest
from ...platform import is_win32, is_darwin
from ...repository import Repository
from ...helpers import CommandError, BackupPermissionError
from .. import has_lchflags
from .. import changedir
from .. import (
    are_symlinks_supported,
    are_hardlinks_supported,
    are_fifos_supported,
    is_utime_fully_supported,
    is_birthtime_fully_supported,
    same_ts_ns,
    is_root,
)
from . import (
    cmd,
    generate_archiver_tests,
    create_test_files,
    assert_dirs_equal,
    create_regular_file,
    requires_hardlinks,
    _create_test_caches,
    _create_test_tagged,
    _create_test_keep_tagged,
    _assert_test_caches,
    _assert_test_tagged,
    _assert_test_keep_tagged,
    RK_ENCRYPTION,
)

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_basic_functionality(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("test_basic_functionality seems incompatible with fakeroot and/or the binary.")
    have_root = create_test_files(archiver.input_path)
    # fork required to test show-rc output
    output = cmd(archiver, "repo-create", RK_ENCRYPTION, "--show-version", "--show-rc", fork=True)
    assert "borgbackup version" in output
    assert "terminating with success status, rc 0" in output

    cmd(archiver, "create", "test", "input")
    output = cmd(archiver, "create", "--stats", "test.2", "input")
    assert "Archive name: test.2" in output

    with changedir("output"):
        cmd(archiver, "extract", "test")

    list_output = cmd(archiver, "repo-list")
    assert "test" in list_output
    assert "test.2" in list_output

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
        # remove the file we did not back up, so input and output become equal
        expected.remove("input/flagfile")  # this file is UF_NODUMP
        os.remove(os.path.join("input", "flagfile"))

    list_output = cmd(archiver, "list", "test", "--short")
    for name in expected:
        assert name in list_output
    assert_dirs_equal("input", "output/input")

    info_output = cmd(archiver, "info", "-a", "test")
    item_count = 5 if has_lchflags else 6  # one file is UF_NODUMP
    assert "Number of files: %d" % item_count in info_output
    shutil.rmtree(archiver.cache_path)
    info_output2 = cmd(archiver, "info", "-a", "test")

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
    assert filter(info_output) == filter(info_output2)


def test_archived_paths(archivers, request):
    # As borg comes from the POSIX (Linux, UNIX) world, a lot of stuff assumes path separators
    # to be slashes "/", e.g.: in archived items, for pattern matching.
    # To make our lives easier and to support cross-platform extraction we always use slashes.
    # Similarly, archived paths are expected to be full, but relative (have no leading slash).
    archiver = request.getfixturevalue(archivers)
    full_path = os.path.abspath(os.path.join(archiver.input_path, "test"))
    # remove windows drive letter, if any:
    posix_path = full_path[2:] if full_path[1] == ":" else full_path
    # only needed on Windows in case there are backslashes:
    posix_path = posix_path.replace("\\", "/")
    # no leading slash in borg archives:
    archived_path = posix_path.lstrip("/")
    create_regular_file(archiver.input_path, "test")
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "test", "input", posix_path)
    # "input" directory is recursed into, "input/test" is discovered and joined by borg's recursion.
    # posix_path was directly given as a cli argument and should end up as archive_path in the borg archive.
    expected_paths = sorted(["input", "input/test", archived_path])

    # check path in archived items:
    archive_list = cmd(archiver, "list", "test", "--short")
    assert expected_paths == sorted([path for path in archive_list.splitlines() if path])

    # check path in archived items (json):
    archive_list = cmd(archiver, "list", "test", "--json-lines")
    assert expected_paths == sorted([json.loads(line)["path"] for line in archive_list.splitlines() if line])


@requires_hardlinks
def test_create_duplicate_root(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # setup for #5603
    path_a = os.path.join(archiver.input_path, "a")
    path_b = os.path.join(archiver.input_path, "b")
    os.mkdir(path_a)
    os.mkdir(path_b)
    hl_a = os.path.join(path_a, "hardlink")
    hl_b = os.path.join(path_b, "hardlink")
    create_regular_file(archiver.input_path, hl_a, contents=b"123456")
    os.link(hl_a, hl_b)
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "test", "input", "input")  # give input twice!
    # test if created archive has 'input' contents twice:
    archive_list = cmd(archiver, "list", "test", "--json-lines")
    paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
    # we have all fs items exactly once!
    assert sorted(paths) == ["input", "input/a", "input/a/hardlink", "input/b", "input/b/hardlink"]


def test_create_unreadable_parent(archiver):
    parent_dir = os.path.join(archiver.input_path, "parent")
    root_dir = os.path.join(archiver.input_path, "parent", "root")
    os.mkdir(parent_dir)
    os.mkdir(root_dir)
    os.chmod(parent_dir, 0o111)  # --x--x--x == parent dir traversable, but not readable
    try:
        cmd(archiver, "repo-create", "--encryption=none")
        # issue #7746: we *can* read root_dir and we *can* traverse parent_dir, so this should work:
        cmd(archiver, "create", "test", root_dir)
    finally:
        os.chmod(parent_dir, 0o771)  # otherwise cleanup after this test fails


@pytest.mark.skipif(is_win32, reason="unix sockets not available on windows")
def test_unix_socket(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(os.path.join(temp_dir, "unix-socket"))
    except PermissionError as err:
        if err.errno == errno.EPERM:
            pytest.skip("unix sockets disabled or not supported")
        elif err.errno == errno.EACCES:
            pytest.skip("permission denied to create unix sockets")
    cmd(archiver, "create", "test", "input")
    sock.close()
    with changedir("output"):
        cmd(archiver, "extract", "test")
        print(f"{temp_dir}/unix-socket")
        assert not os.path.exists(f"{temp_dir}/unix-socket")


@pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot setup and execute test without utime")
@pytest.mark.skipif(not is_birthtime_fully_supported(), reason="cannot setup and execute test without birth time")
def test_nobirthtime(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    birthtime, mtime, atime = 946598400, 946684800, 946771200
    os.utime("input/file1", (atime, birthtime))
    os.utime("input/file1", (atime, mtime))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "--nobirthtime")
    with changedir("output"):
        cmd(archiver, "extract", "test")
    sti = os.stat("input/file1")
    sto = os.stat("output/input/file1")
    assert same_ts_ns(sti.st_birthtime * 1e9, birthtime * 1e9)
    assert same_ts_ns(sto.st_birthtime * 1e9, mtime * 1e9)
    assert same_ts_ns(sti.st_mtime_ns, sto.st_mtime_ns)
    assert same_ts_ns(sto.st_mtime_ns, mtime * 1e9)


def test_create_stdin(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_data = b"\x00foo\n\nbar\n   \n"
    cmd(archiver, "create", "test", "-", input=input_data)
    item = json.loads(cmd(archiver, "list", "test", "--json-lines"))
    assert item["size"] == len(input_data)
    assert item["path"] == "stdin"
    extracted_data = cmd(archiver, "extract", "test", "--stdout", binary_output=True)
    assert extracted_data == input_data


def test_create_erroneous_file(archivers, request):
    archiver = request.getfixturevalue(archivers)
    chunk_size = 1000  # fixed chunker with this size
    create_regular_file(archiver.input_path, os.path.join(archiver.input_path, "file1"), size=chunk_size * 2)
    create_regular_file(archiver.input_path, os.path.join(archiver.input_path, "file2"), size=chunk_size * 2)
    create_regular_file(archiver.input_path, os.path.join(archiver.input_path, "file3"), size=chunk_size * 2)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    flist = "".join(f"input/file{n}\n" for n in range(1, 4))
    out = cmd(
        archiver,
        "create",
        f"--chunker-params=fail,{chunk_size},rrrEEErrrr",
        "--paths-from-stdin",
        "--list",
        "test",
        input=flist.encode(),
        exit_code=0,
    )
    assert "retry: 3 of " in out
    assert "E input/file2" not in out  # we managed to read it in the 3rd retry (after 3 failed reads)
    # repo looking good overall? checks for rc == 0.
    cmd(archiver, "check", "--debug")
    # check files in created archive
    out = cmd(archiver, "list", "test")
    assert "input/file1" in out
    assert "input/file2" in out
    assert "input/file3" in out


@pytest.mark.skipif(is_root(), reason="test must not be run as (fake)root")
def test_create_no_permission_file(archivers, request):
    archiver = request.getfixturevalue(archivers)
    file_path = os.path.join(archiver.input_path, "file")
    create_regular_file(archiver.input_path, file_path + "1", size=1000)
    create_regular_file(archiver.input_path, file_path + "2", size=1000)
    create_regular_file(archiver.input_path, file_path + "3", size=1000)
    # revoke read permissions on file2 for everybody, including us:
    if is_win32:
        subprocess.run(["icacls.exe", file_path + "2", "/deny", "everyone:(R)"])
    else:
        # note: this will NOT take away read permissions for root
        os.chmod(file_path + "2", 0o000)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    flist = "".join(f"input/file{n}\n" for n in range(1, 4))
    expected_ec = BackupPermissionError("open", OSError(13, "permission denied")).exit_code
    if expected_ec == EXIT_ERROR:  # workaround, TODO: fix it
        expected_ec = EXIT_WARNING
    out = cmd(
        archiver,
        "create",
        "--paths-from-stdin",
        "--list",
        "test",
        input=flist.encode(),
        exit_code=expected_ec,  # WARNING status: could not back up file2.
    )
    assert "retry: 1 of " not in out  # retries were NOT attempted!
    assert "E input/file2" in out  # no permissions!
    # repo looking good overall? checks for rc == 0.
    cmd(archiver, "check", "--debug")
    # check files in created archive
    out = cmd(archiver, "list", "test")
    assert "input/file1" in out
    assert "input/file2" not in out  # it skipped file2
    assert "input/file3" in out


def test_sanitized_stdin_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--stdin-name", "./a//path", "test", "-", input=b"")
    item = json.loads(cmd(archiver, "list", "test", "--json-lines"))
    assert item["path"] == "a/path"


def test_dotdot_stdin_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "--stdin-name", "foo/../bar", "test", "-", input=b"", exit_code=2)
    assert output.endswith("'..' element in path 'foo/../bar'" + os.linesep)


def test_dot_stdin_name(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "--stdin-name", "./", "test", "-", input=b"", exit_code=2)
    assert output.endswith("'./' is not a valid file name" + os.linesep)


def test_create_content_from_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_data = "some test content"
    name = "a/b/c"
    cmd(archiver, "create", "--stdin-name", name, "--content-from-command", "test", "--", "echo", input_data)
    item = json.loads(cmd(archiver, "list", "test", "--json-lines"))
    assert item["size"] == len(input_data) + 1  # `echo` adds newline
    assert item["path"] == name
    extracted_data = cmd(archiver, "extract", "test", "--stdout")
    assert extracted_data == input_data + "\n"


def test_create_content_from_command_with_failed_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        output = cmd(
            archiver, "create", "--content-from-command", "test", "--", "sh", "-c", "exit 73;", exit_code=expected_ec
        )
        assert output.endswith("Command 'sh' exited with status 73" + os.linesep)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "create", "--content-from-command", "test", "--", "sh", "-c", "exit 73;")
    archive_list = json.loads(cmd(archiver, "repo-list", "--json"))
    assert archive_list["archives"] == []


def test_create_content_from_command_missing_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "test", "--content-from-command", exit_code=2)
    assert output.endswith("No command given." + os.linesep)


def test_create_paths_from_stdin(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir1/file2", size=1024 * 80)
    create_regular_file(archiver.input_path, "dir1/file3", size=1024 * 80)
    create_regular_file(archiver.input_path, "file4", size=1024 * 80)
    input_data = b"input/file1\0input/dir1\0input/file4"
    cmd(archiver, "create", "test", "--paths-from-stdin", "--paths-delimiter", "\\0", input=input_data)
    archive_list = cmd(archiver, "list", "test", "--json-lines")
    paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
    assert paths == ["input/file1", "input/dir1", "input/file4"]


def test_create_paths_from_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    create_regular_file(archiver.input_path, "file3", size=1024 * 80)
    create_regular_file(archiver.input_path, "file4", size=1024 * 80)
    input_data = "input/file1\ninput/file2\ninput/file3"
    if is_win32:
        with open("filenames.cmd", "w") as script:
            for filename in input_data.splitlines():
                script.write(f"@echo {filename}\n")
    cmd(archiver, "create", "--paths-from-command", "test", "--", "filenames.cmd" if is_win32 else "echo", input_data)
    archive_list = cmd(archiver, "list", "test", "--json-lines")
    paths = [json.loads(line)["path"] for line in archive_list.split("\n") if line]
    assert paths == ["input/file1", "input/file2", "input/file3"]


def test_create_paths_from_command_with_failed_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        expected_ec = CommandError().exit_code
        output = cmd(
            archiver, "create", "--paths-from-command", "test", "--", "sh", "-c", "exit 73;", exit_code=expected_ec
        )
        assert output.endswith("Command 'sh' exited with status 73" + os.linesep)
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "create", "--paths-from-command", "test", "--", "sh", "-c", "exit 73;")
    archive_list = json.loads(cmd(archiver, "repo-list", "--json"))
    assert archive_list["archives"] == []


def test_create_paths_from_command_missing_command(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "test", "--paths-from-command", exit_code=2)
    assert output.endswith("No command given." + os.linesep)


def test_create_without_root(archivers, request):
    """test create without a root"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", exit_code=2)


def test_create_pattern_root(archivers, request):
    """test create with only a root pattern"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    output = cmd(archiver, "create", "test", "-v", "--list", "--pattern=R input")
    assert "A input/file1" in output
    assert "A input/file2" in output


def test_create_pattern(archivers, request):
    """test file patterns during create"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    create_regular_file(archiver.input_path, "file_important", size=1024 * 80)
    output = cmd(
        archiver, "create", "-v", "--list", "--pattern=+input/file_important", "--pattern=-input/file*", "test", "input"
    )
    assert "A input/file_important" in output
    assert "- input/file1" in output
    assert "- input/file2" in output


def test_create_pattern_file(archivers, request):
    """test file patterns during create"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    create_regular_file(archiver.input_path, "otherfile", size=1024 * 80)
    create_regular_file(archiver.input_path, "file_important", size=1024 * 80)
    output = cmd(
        archiver,
        "create",
        "-v",
        "--list",
        "--pattern=-input/otherfile",
        "--patterns-from=" + archiver.patterns_file_path,
        "test",
        "input",
    )
    assert "A input/file_important" in output
    assert "- input/file1" in output
    assert "- input/file2" in output
    assert "- input/otherfile" in output


def test_create_pattern_exclude_folder_but_recurse(archivers, request):
    """test when patterns exclude a parent folder, but include a child"""
    archiver = request.getfixturevalue(archivers)
    patterns_file_path2 = os.path.join(archiver.tmpdir, "patterns2")
    with open(patterns_file_path2, "wb") as fd:
        fd.write(b"+ input/x/b\n- input/x*\n")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "x/a/foo_a", size=1024 * 80)
    create_regular_file(archiver.input_path, "x/b/foo_b", size=1024 * 80)
    create_regular_file(archiver.input_path, "y/foo_y", size=1024 * 80)
    output = cmd(archiver, "create", "-v", "--list", "--patterns-from=" + patterns_file_path2, "test", "input")
    assert "- input/x/a/foo_a" in output
    assert "A input/x/b/foo_b" in output
    assert "A input/y/foo_y" in output


def test_create_pattern_exclude_folder_no_recurse(archivers, request):
    """test when patterns exclude a parent folder, but include a child"""
    archiver = request.getfixturevalue(archivers)
    patterns_file_path2 = os.path.join(archiver.tmpdir, "patterns2")
    with open(patterns_file_path2, "wb") as fd:
        fd.write(b"+ input/x/b\n! input/x*\n")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "x/a/foo_a", size=1024 * 80)
    create_regular_file(archiver.input_path, "x/b/foo_b", size=1024 * 80)
    create_regular_file(archiver.input_path, "y/foo_y", size=1024 * 80)
    output = cmd(archiver, "create", "-v", "--list", "--patterns-from=" + patterns_file_path2, "test", "input")
    assert "input/x/a/foo_a" not in output
    assert "input/x/a" not in output
    assert "A input/y/foo_y" in output


def test_create_pattern_intermediate_folders_first(archivers, request):
    """test that intermediate folders appear first when patterns exclude a parent folder but include a child"""
    archiver = request.getfixturevalue(archivers)
    patterns_file_path2 = os.path.join(archiver.tmpdir, "patterns2")
    with open(patterns_file_path2, "wb") as fd:
        fd.write(b"+ input/x/a\n+ input/x/b\n- input/x*\n")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "x/a/foo_a", size=1024 * 80)
    create_regular_file(archiver.input_path, "x/b/foo_b", size=1024 * 80)
    with changedir("input"):
        cmd(archiver, "create", "--patterns-from=" + patterns_file_path2, "test", ".")
    # list the archive and verify that the "intermediate" folders appear before
    # their contents
    out = cmd(archiver, "list", "test", "--format", "{type} {path}{NL}")
    out_list = out.splitlines()
    assert "d x/a" in out_list
    assert "d x/b" in out_list
    assert out_list.index("d x/a") < out_list.index("- x/a/foo_a")
    assert out_list.index("d x/b") < out_list.index("- x/b/foo_b")


def test_create_archivename_with_placeholder(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    ts = "1999-12-31T23:59:59"
    name_given = "test-{now}"  # placeholder in archive name gets replaced by borg
    name_expected = f"test-{ts}"  # placeholder in f-string gets replaced by python
    cmd(archiver, "create", f"--timestamp={ts}", name_given, "input")
    list_output = cmd(archiver, "repo-list")
    assert name_expected in list_output


def test_exclude_caches(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_caches(archiver)
    cmd(archiver, "create", "test", "input", "--exclude-caches")
    _assert_test_caches(archiver)


def test_exclude_tagged(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_tagged(archiver)
    cmd(archiver, "create", "test", "input", "--exclude-if-present", ".NOBACKUP", "--exclude-if-present", "00-NOBACKUP")
    _assert_test_tagged(archiver)


def test_exclude_keep_tagged(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_keep_tagged(archiver)
    cmd(
        archiver,
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
    _assert_test_keep_tagged(archiver)


def test_path_sanitation(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "dir1/dir2/file", size=1024 * 80)
    with changedir("input/dir1/dir2"):
        cmd(archiver, "create", "test", "../../../input/dir1/../dir1/dir2/..")
    output = cmd(archiver, "list", "test")
    assert ".." not in output
    assert " input/dir1/dir2/file" in output


def test_exclude_sanitation(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    with changedir("input"):
        cmd(archiver, "create", "test1", ".", "--exclude=file1")
    with changedir("output"):
        cmd(archiver, "extract", "test1")
    assert sorted(os.listdir("output")) == ["file2"]
    with changedir("input"):
        cmd(archiver, "create", "test2", ".", "--exclude=./file1")
    with changedir("output"):
        cmd(archiver, "extract", "test2")
    assert sorted(os.listdir("output")) == ["file2"]
    cmd(archiver, "create", "test3", "input", "--exclude=input/./file1")
    with changedir("output"):
        cmd(archiver, "extract", "test3")
    assert sorted(os.listdir("output/input")) == ["file2"]


def test_repeated_files(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "input")


@pytest.mark.skipif("BORG_TESTS_IGNORE_MODES" in os.environ, reason="modes unreliable")
@pytest.mark.skipif(is_win32, reason="modes unavailable on Windows")
def test_umask(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    mode = os.stat(archiver.repository_path).st_mode
    assert stat.S_IMODE(mode) == 0o700


def test_create_dry_run(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--dry-run", "test", "input")
    # Make sure no archive has been created
    with Repository(archiver.repository_path) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        assert manifest.archives.count() == 0


def test_progress_on(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "test4", "input", "--progress")
    assert "\r" in output


def test_progress_off(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "test5", "input")
    assert "\r" not in output


def test_file_status(archivers, request):
    """test that various file status show expected results
    clearly incomplete: only tests for the weird "unchanged" status for now"""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "--list", "test", "input")
    assert "A input/file1" in output
    assert "A input/file2" in output
    # should find first file as unmodified
    output = cmd(archiver, "create", "--list", "test", "input")
    assert "U input/file1" in output
    # although surprising, this is expected. For why, see:
    # https://borgbackup.readthedocs.org/en/latest/faq.html#i-am-seeing-a-added-status-for-a-unchanged-file
    assert "A input/file2" in output


@pytest.mark.skipif(
    is_win32, reason="ctime attribute is file creation time on Windows"
)  # see https://docs.python.org/3/library/os.html#os.stat_result.st_ctime
def test_file_status_cs_cache_mode(archivers, request):
    archiver = request.getfixturevalue(archivers)
    """test that a changed file with faked "previous" mtime still gets backed up in ctime,size cache_mode"""
    create_regular_file(archiver.input_path, "file1", contents=b"123")
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=10)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "--list", "--files-cache=ctime,size")
    # modify file1, but cheat with the mtime (and atime) and also keep same size:
    st = os.stat("input/file1")
    create_regular_file(archiver.input_path, "file1", contents=b"321")
    os.utime("input/file1", ns=(st.st_atime_ns, st.st_mtime_ns))
    # this mode uses ctime for change detection, so it should find file1 as modified
    output = cmd(archiver, "create", "test", "input", "--list", "--files-cache=ctime,size")
    assert "M input/file1" in output


def test_file_status_ms_cache_mode(archivers, request):
    """test that a chmod'ed file with no content changes does not get chunked again in mtime,size cache_mode"""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=10)
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=10)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--list", "--files-cache=mtime,size", "test", "input")
    # change mode of file1, no content change:
    st = os.stat("input/file1")
    os.chmod("input/file1", st.st_mode ^ stat.S_IRWXO)  # this triggers a ctime change, but mtime is unchanged
    # this mode uses mtime for change detection, so it should find file1 as unmodified
    output = cmd(archiver, "create", "--list", "--files-cache=mtime,size", "test", "input")
    assert "U input/file1" in output


def test_file_status_rc_cache_mode(archivers, request):
    """test that files get rechunked unconditionally in rechunk,ctime cache mode"""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=10)
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=10)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--list", "--files-cache=rechunk,ctime", "test", "input")
    # no changes here, but this mode rechunks unconditionally
    output = cmd(archiver, "create", "--list", "--files-cache=rechunk,ctime", "test", "input")
    assert "A input/file1" in output


def test_file_status_excluded(archivers, request):
    """test that excluded paths are listed"""
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    if has_lchflags:
        create_regular_file(archiver.input_path, "file3", size=1024 * 80)
        platform.set_flags(os.path.join(archiver.input_path, "file3"), stat.UF_NODUMP)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "create", "--list", "test", "input")
    assert "A input/file1" in output
    assert "A input/file2" in output
    if has_lchflags:
        assert "- input/file3" in output
    # should find second file as excluded
    output = cmd(archiver, "create", "test", "input", "--list", "--exclude", "*/file2")
    assert "U input/file1" in output
    assert "- input/file2" in output
    if has_lchflags:
        assert "- input/file3" in output


def test_file_status_counters(archivers, request):
    """Test file status counters in the stats of `borg create --stats`"""
    archiver = request.getfixturevalue(archivers)

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
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Archive an empty dir
    result = cmd(archiver, "create", "--stats", "test_archive", archiver.input_path)
    result = to_dict(result)
    assert result["Added files"] == 0
    assert result["Unchanged files"] == 0
    assert result["Modified files"] == 0
    # Archive a dir with two added files
    create_regular_file(archiver.input_path, "testfile1", contents=b"test1")
    time.sleep(1.0 if is_darwin else 0.01)  # testfile2 must have newer timestamps than testfile1
    create_regular_file(archiver.input_path, "testfile2", contents=b"test2")
    result = cmd(archiver, "create", "--stats", "test_archive", archiver.input_path)
    result = to_dict(result)
    assert result["Added files"] == 2
    assert result["Unchanged files"] == 0
    assert result["Modified files"] == 0
    # Archive a dir with 1 unmodified file and 1 modified
    create_regular_file(archiver.input_path, "testfile1", contents=b"new data")
    result = cmd(archiver, "create", "--stats", "test_archive", archiver.input_path)
    result = to_dict(result)
    # Should process testfile2 as added because of
    # https://borgbackup.readthedocs.io/en/stable/faq.html#i-am-seeing-a-added-status-for-an-unchanged-file
    assert result["Added files"] == 1
    assert result["Unchanged files"] == 0
    assert result["Modified files"] == 1


def test_create_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_info = json.loads(cmd(archiver, "create", "--json", "test", "input"))
    # The usual keys
    assert "encryption" in create_info
    assert "repository" in create_info
    assert "cache" in create_info
    assert "last_modified" in create_info["repository"]

    archive = create_info["archive"]
    assert archive["name"] == "test"
    assert isinstance(archive["command_line"], str)
    assert isinstance(archive["duration"], float)
    assert len(archive["id"]) == 64
    assert "stats" in archive


def test_create_topical(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    time.sleep(1)  # file2 must have newer timestamps than file1
    create_regular_file(archiver.input_path, "file2", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # no listing by default
    output = cmd(archiver, "create", "test", "input")
    assert "file1" not in output
    # shouldn't be listed even if unchanged
    output = cmd(archiver, "create", "test", "input")
    assert "file1" not in output
    # should list the file as unchanged
    output = cmd(archiver, "create", "test", "input", "--list", "--filter=U")
    assert "file1" in output
    # should *not* list the file as changed
    output = cmd(archiver, "create", "test", "input", "--list", "--filter=AM")
    assert "file1" not in output
    # change the file
    create_regular_file(archiver.input_path, "file1", size=1024 * 100)
    # should list the file as changed
    output = cmd(archiver, "create", "test", "input", "--list", "--filter=AM")
    assert "file1" in output


# @pytest.mark.skipif(not are_fifos_supported() or is_cygwin, reason="FIFOs not supported, hangs on cygwin")
@pytest.mark.skip(reason="This test is problematic and should be skipped")
def test_create_read_special_symlink(archivers, request):
    archiver = request.getfixturevalue(archivers)
    from threading import Thread

    def fifo_feeder(fifo_fn, data):
        fd = os.open(fifo_fn, os.O_WRONLY)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    data = b"foobar" * 1000

    fifo_fn = os.path.join(archiver.input_path, "fifo")
    link_fn = os.path.join(archiver.input_path, "link_fifo")
    os.mkfifo(fifo_fn)
    os.symlink(fifo_fn, link_fn)

    t = Thread(target=fifo_feeder, args=(fifo_fn, data))
    t.start()
    try:
        cmd(archiver, "create", "--read-special", "test", "input/link_fifo")
    finally:
        # In case `borg create` failed to open FIFO, read all data to avoid join() hanging.
        fd = os.open(fifo_fn, os.O_RDONLY | os.O_NONBLOCK)
        try:
            os.read(fd, len(data))
        except OSError:
            # fails on FreeBSD 13 with BlockingIOError
            pass
        finally:
            os.close(fd)
        t.join()
    with changedir("output"):
        cmd(archiver, "extract", "test")
        fifo_fn = "input/link_fifo"
        with open(fifo_fn, "rb") as f:
            extracted_data = f.read()
    assert extracted_data == data


@pytest.mark.skipif(not are_symlinks_supported(), reason="symlinks not supported")
def test_create_read_special_broken_symlink(archivers, request):
    archiver = request.getfixturevalue(archivers)
    os.symlink("somewhere does not exist", os.path.join(archiver.input_path, "link"))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "--read-special", "test", "input")
    output = cmd(archiver, "list", "test")
    assert "input/link -> somewhere does not exist" in output


def test_create_dotslash_hack(archivers, request):
    archiver = request.getfixturevalue(archivers)
    os.makedirs(os.path.join(archiver.input_path, "first", "secondA", "thirdA"))
    os.makedirs(os.path.join(archiver.input_path, "first", "secondB", "thirdB"))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input/first/./")  # hack!
    output = cmd(archiver, "list", "test")
    # dir levels left of slashdot (= input, first) not in archive:
    assert "input" not in output
    assert "input/first" not in output
    assert "input/first/secondA" not in output
    assert "input/first/secondA/thirdA" not in output
    assert "input/first/secondB" not in output
    assert "input/first/secondB/thirdB" not in output
    assert "first" not in output
    assert "first/secondA" not in output
    assert "first/secondA/thirdA" not in output
    assert "first/secondB" not in output
    assert "first/secondB/thirdB" not in output
    # dir levels right of slashdot are in archive:
    assert "secondA" in output
    assert "secondA/thirdA" in output
    assert "secondB" in output
    assert "secondB/thirdB" in output


def test_log_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    log = cmd(archiver, "create", "test", "input", "--log-json", "--list", "--debug")
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


def test_common_options(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    log = cmd(archiver, "--debug", "create", "test", "input")
    assert "security: read previous location" in log


def test_create_big_zeros_files(archivers, request):
    """Test creating an archive from 10 files with 10MB zeros each."""
    archiver = request.getfixturevalue(archivers)
    # Create 10 files with 10,000,000 bytes of zeros each
    count, size = 10, 10 * 1000 * 1000
    assert size <= len(zeros)
    for i in range(count):
        create_regular_file(archiver.input_path, f"zeros_{i}", contents=memoryview(zeros)[:size])
    # Create repository and archive
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    # Extract the archive to verify contents
    with tempfile.TemporaryDirectory() as extract_path:
        with changedir(extract_path):
            cmd(archiver, "extract", "test")

            # Verify that the extracted files have the correct contents
            for i in range(count):
                extracted_file_path = os.path.join(extract_path, "input", f"zeros_{i}")
                with open(extracted_file_path, "rb") as f:
                    extracted_data = f.read()
                    # Verify the file contains only zeros and has the correct size
                    assert extracted_data == bytes(size)
                    assert len(extracted_data) == size

            # Also verify the directory structure matches
            assert_dirs_equal(archiver.input_path, os.path.join(extract_path, "input"))


def test_create_big_random_files(archivers, request):
    """Test creating an archive from 10 files with 10MB random data each."""
    archiver = request.getfixturevalue(archivers)
    # Create 10 files with 10,000,000 bytes of random data each
    count, size = 10, 10 * 1000 * 1000
    random_data = {}
    for i in range(count):
        data = os.urandom(size)
        random_data[i] = data
        create_regular_file(archiver.input_path, f"random_{i}", contents=data)
    # Create repository and archive
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    # Extract the archive to verify contents
    with tempfile.TemporaryDirectory() as extract_path:
        with changedir(extract_path):
            cmd(archiver, "extract", "test")

            # Verify that the extracted files have the correct contents
            for i in range(count):
                extracted_file_path = os.path.join(extract_path, "input", f"random_{i}")
                with open(extracted_file_path, "rb") as f:
                    extracted_data = f.read()
                    # Verify the file contains the original random data and has the correct size
                    assert extracted_data == random_data[i]
                    assert len(extracted_data) == size

            # Also verify the directory structure matches
            assert_dirs_equal(archiver.input_path, os.path.join(extract_path, "input"))


def test_create_with_compression_algorithms(archivers, request):
    """Test creating archives with different compression algorithms."""
    archiver = request.getfixturevalue(archivers)

    # Create test files: 5 files with zeros (highly compressible) and 5 with random data (incompressible)
    count, size = 5, 1 * 1000 * 1000  # 1MB per file
    random_data = {}

    # Create zeros files
    for i in range(count):
        create_regular_file(archiver.input_path, f"zeros_{i}", contents=memoryview(zeros)[:size])

    # Create random files
    for i in range(count):
        data = os.urandom(size)
        random_data[i] = data
        create_regular_file(archiver.input_path, f"random_{i}", contents=data)

    # Create repository
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Test different compression algorithms
    algorithms = [
        "none",  # No compression
        "lz4",  # Fast compression
        "zlib,6",  # Medium compression
        "zstd,3",  # Good compression/speed balance
        "lzma,6",  # High compression
    ]

    for algo in algorithms:
        # Create archive with specific compression algorithm
        archive_name = f"test_{algo.replace(',', '_')}"
        cmd(archiver, "create", "--compression", algo, archive_name, "input")

        # Extract the archive to verify contents
        with tempfile.TemporaryDirectory() as extract_path:
            with changedir(extract_path):
                cmd(archiver, "extract", archive_name)

                # Verify zeros files
                for i in range(count):
                    extracted_file_path = os.path.join(extract_path, "input", f"zeros_{i}")
                    with open(extracted_file_path, "rb") as f:
                        extracted_data = f.read()
                        # Verify the file contains only zeros and has the correct size
                        assert extracted_data == bytes(size)
                        assert len(extracted_data) == size

                # Verify random files
                for i in range(count):
                    extracted_file_path = os.path.join(extract_path, "input", f"random_{i}")
                    with open(extracted_file_path, "rb") as f:
                        extracted_data = f.read()
                        # Verify the file contains the original random data and has the correct size
                        assert extracted_data == random_data[i]
                        assert len(extracted_data) == size

                # Also verify the directory structure matches
                assert_dirs_equal(archiver.input_path, os.path.join(extract_path, "input"))
