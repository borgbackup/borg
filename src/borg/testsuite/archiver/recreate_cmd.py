import os
import re
from datetime import datetime

import pytest

from ...constants import *  # NOQA
from ...helpers import CommandError
from .. import changedir, are_hardlinks_supported
from . import (
    _create_test_caches,
    _create_test_tagged,
    _create_test_keep_tagged,
    _assert_test_caches,
    _assert_test_tagged,
    _assert_test_keep_tagged,
    _extract_hardlinks_setup,
    generate_archiver_tests,
    check_cache,
    cmd,
    create_regular_file,
    create_test_files,
    RK_ENCRYPTION,
)

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_recreate_exclude_caches(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_caches(archiver)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "recreate", "-a", "test", "--exclude-caches")
    _assert_test_caches(archiver)


def test_recreate_exclude_tagged(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_tagged(archiver)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "recreate", "-a", "test", "--exclude-if-present", ".NOBACKUP", "--exclude-if-present", "00-NOBACKUP")
    _assert_test_tagged(archiver)


def test_recreate_exclude_keep_tagged(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_test_keep_tagged(archiver)
    cmd(archiver, "create", "test", "input")
    cmd(
        archiver,
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
    _assert_test_keep_tagged(archiver)


@pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
def test_recreate_hardlinked_tags(archivers, request):  # test for issue #4911
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", "--encryption=none")
    create_regular_file(
        archiver.input_path, "file1", contents=CACHE_TAG_CONTENTS
    )  # "wrong" filename, but correct tag contents
    os.mkdir(os.path.join(archiver.input_path, "subdir"))  # to make sure the tag is encountered *after* file1
    os.link(
        os.path.join(archiver.input_path, "file1"), os.path.join(archiver.input_path, "subdir", CACHE_TAG_NAME)
    )  # correct tag name, hardlink to file1
    cmd(archiver, "create", "test", "input")
    # in the "test" archive, we now have, in this order:
    # - a regular file item for "file1"
    # - a hardlink item for "CACHEDIR.TAG" referring back to file1 for its contents
    cmd(archiver, "recreate", "test", "--exclude-caches", "--keep-exclude-tags")
    # if issue #4911 is present, the recreate will crash with a KeyError for "input/file1"


def test_recreate_target_rc(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "recreate", "--target=asdf", exit_code=2)
        assert "Need to specify single archive" in output
    else:
        with pytest.raises(CommandError):
            cmd(archiver, "recreate", "--target=asdf")


def test_recreate_target(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    check_cache(archiver)
    cmd(archiver, "create", "test0", "input")
    check_cache(archiver)
    original_archive = cmd(archiver, "rlist")
    cmd(archiver, "recreate", "test0", "input/dir2", "-e", "input/dir2/file3", "--target=new-archive")
    check_cache(archiver)

    archives = cmd(archiver, "rlist")
    assert original_archive in archives
    assert "new-archive" in archives

    listing = cmd(archiver, "list", "new-archive", "--short")
    assert "file1" not in listing
    assert "dir2/file2" in listing
    assert "dir2/file3" not in listing


def test_recreate_basic(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    create_regular_file(archiver.input_path, "dir2/file3", size=1024 * 80)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test0", "input")
    cmd(archiver, "recreate", "test0", "input/dir2", "-e", "input/dir2/file3")
    check_cache(archiver)
    listing = cmd(archiver, "list", "test0", "--short")
    assert "file1" not in listing
    assert "dir2/file2" in listing
    assert "dir2/file3" not in listing


@pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
def test_recreate_subtree_hardlinks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # This is essentially the same problem set as in test_extract_hardlinks
    _extract_hardlinks_setup(archiver)
    cmd(archiver, "create", "test2", "input")
    cmd(archiver, "recreate", "-a", "test", "input/dir1")
    check_cache(archiver)
    with changedir("output"):
        cmd(archiver, "extract", "test")
        assert os.stat("input/dir1/hardlink").st_nlink == 2
        assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
        assert os.stat("input/dir1/aaaa").st_nlink == 2
        assert os.stat("input/dir1/source2").st_nlink == 2
    with changedir("output"):
        cmd(archiver, "extract", "test2")
        assert os.stat("input/dir1/hardlink").st_nlink == 4


def test_recreate_rechunkify(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with open(os.path.join(archiver.input_path, "large_file"), "wb") as fd:
        fd.write(b"a" * 280)
        fd.write(b"b" * 280)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input", "--chunker-params", "7,9,8,128")
    cmd(archiver, "create", "test2", "input", "--files-cache=disabled")
    chunks_list = cmd(archiver, "list", "test1", "input/large_file", "--format", "{num_chunks} {unique_chunks}")
    num_chunks, unique_chunks = map(int, chunks_list.split(" "))
    # test1 and test2 do not deduplicate
    assert num_chunks == unique_chunks
    cmd(archiver, "recreate", "--chunker-params", "default")
    check_cache(archiver)
    # test1 and test2 do deduplicate after recreate
    assert int(cmd(archiver, "list", "test1", "input/large_file", "--format={size}"))
    assert not int(cmd(archiver, "list", "test1", "input/large_file", "--format", "{unique_chunks}"))


def test_recreate_fixed_rechunkify(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with open(os.path.join(archiver.input_path, "file"), "wb") as fd:
        fd.write(b"a" * 8192)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "--chunker-params", "7,9,8,128")
    output = cmd(archiver, "list", "test", "input/file", "--format", "{num_chunks}")
    num_chunks = int(output)
    assert num_chunks > 2
    cmd(archiver, "recreate", "--chunker-params", "fixed,4096")
    output = cmd(archiver, "list", "test", "input/file", "--format", "{num_chunks}")
    num_chunks = int(output)
    assert num_chunks == 2


def test_recreate_no_rechunkify(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with open(os.path.join(archiver.input_path, "file"), "wb") as fd:
        fd.write(b"a" * 8192)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    # first create an archive with non-default chunker params:
    cmd(archiver, "create", "test", "input", "--chunker-params", "7,9,8,128")
    output = cmd(archiver, "list", "test", "input/file", "--format", "{num_chunks}")
    num_chunks = int(output)
    # now recreate the archive and do NOT specify chunker params:
    output = cmd(archiver, "recreate", "--debug", "--exclude", "filename_never_matches", "-a", "test")
    assert "Rechunking" not in output  # we did not give --chunker-params, so it must not rechunk!
    output = cmd(archiver, "list", "test", "input/file", "--format", "{num_chunks}")
    num_chunks_after_recreate = int(output)
    assert num_chunks == num_chunks_after_recreate


def test_recreate_timestamp(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test0", "input")
    cmd(archiver, "recreate", "test0", "--timestamp", "1970-01-02T00:00:00", "--comment", "test")
    info = cmd(archiver, "info", "-a", "test0").splitlines()
    dtime = datetime(1970, 1, 2, 0, 0, 0).astimezone()  # local time in local timezone
    s_time = dtime.strftime("%Y-%m-%d %H:%M:.. %z").replace("+", r"\+")
    assert any([re.search(r"Time \(start\).+ %s" % s_time, item) for item in info])
    assert any([re.search(r"Time \(end\).+ %s" % s_time, item) for item in info])


def test_recreate_dry_run(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "compressible", size=10000)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    archives_before = cmd(archiver, "list", "test")
    cmd(archiver, "recreate", "-n", "-e", "input/compressible")
    check_cache(archiver)
    archives_after = cmd(archiver, "list", "test")
    assert archives_after == archives_before


def test_recreate_skips_nothing_to_do(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    info_before = cmd(archiver, "info", "-a", "test")
    cmd(archiver, "recreate", "--chunker-params", "default")
    check_cache(archiver)
    info_after = cmd(archiver, "info", "-a", "test")
    assert info_before == info_after  # includes archive ID


def test_recreate_list_output(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=0)
    create_regular_file(archiver.input_path, "file2", size=0)
    create_regular_file(archiver.input_path, "file3", size=0)
    create_regular_file(archiver.input_path, "file4", size=0)
    create_regular_file(archiver.input_path, "file5", size=0)
    cmd(archiver, "create", "test", "input")

    output = cmd(archiver, "recreate", "-a", "test", "--list", "--info", "-e", "input/file2")
    check_cache(archiver)
    assert "input/file1" in output
    assert "- input/file2" in output

    output = cmd(archiver, "recreate", "-a", "test", "--list", "-e", "input/file3")
    check_cache(archiver)
    assert "input/file1" in output
    assert "- input/file3" in output

    output = cmd(archiver, "recreate", "-a", "test", "-e", "input/file4")
    check_cache(archiver)
    assert "input/file1" not in output
    assert "- input/file4" not in output

    output = cmd(archiver, "recreate", "-a", "test", "--info", "-e", "input/file5")
    check_cache(archiver)
    assert "input/file1" not in output
    assert "- input/file5" not in output


def test_comment(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)

    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", "input")
    cmd(archiver, "create", "test2", "input", "--comment", "this is the comment")
    cmd(archiver, "create", "test3", "input", "--comment", '"deleted" comment')
    cmd(archiver, "create", "test4", "input", "--comment", "preserved comment")
    assert "Comment: " + os.linesep in cmd(archiver, "info", "-a", "test1")
    assert "Comment: this is the comment" in cmd(archiver, "info", "-a", "test2")

    cmd(archiver, "recreate", "-a", "test1", "--comment", "added comment")
    cmd(archiver, "recreate", "-a", "test2", "--comment", "modified comment")
    cmd(archiver, "recreate", "-a", "test3", "--comment", "")
    cmd(archiver, "recreate", "-a", "test4", "12345")
    assert "Comment: added comment" in cmd(archiver, "info", "-a", "test1")
    assert "Comment: modified comment" in cmd(archiver, "info", "-a", "test2")
    assert "Comment: " + os.linesep in cmd(archiver, "info", "-a", "test3")
    assert "Comment: preserved comment" in cmd(archiver, "info", "-a", "test4")
