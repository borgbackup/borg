import json
import os

from ...constants import *  # NOQA
from . import src_dir, cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_list_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", src_dir)
    output_1 = cmd(archiver, "list", "test")
    output_2 = cmd(
        archiver, "list", "test", "--format", "{mode} {user:6} {group:6} {size:8d} {mtime} {path}{extra}{NEWLINE}"
    )
    output_3 = cmd(archiver, "list", "test", "--format", "{mtime:%s} {path}{NL}")
    assert output_1 == output_2
    assert output_1 != output_3


def test_list_hash(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "empty_file", size=0)
    create_regular_file(archiver.input_path, "amb", contents=b"a" * 1000000)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    output = cmd(archiver, "list", "test", "--format", "{sha256} {path}{NL}")
    assert "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 input/amb" in output
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 input/empty_file" in output


def test_list_chunk_counts(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "empty_file", size=0)
    create_regular_file(archiver.input_path, "two_chunks")
    filename = os.path.join(archiver.input_path, "two_chunks")
    with open(filename, "wb") as fd:
        fd.write(b"abba" * 2000000)
        fd.write(b"baab" * 2000000)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    os.unlink(filename)  # save space on TMPDIR
    output = cmd(archiver, "list", "test", "--format", "{num_chunks} {path}{NL}")
    assert "0 input/empty_file" in output
    assert "2 input/two_chunks" in output


def test_list_size(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "compressible_file", size=10000)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "-C", "lz4", "test", "input")
    output = cmd(archiver, "list", "test", "--format", "{size} {path}{NL}")
    size, path = output.split("\n")[1].split(" ")
    assert int(size) == 10000


def test_list_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")

    list_archive = cmd(archiver, "list", "test", "--json-lines")
    items = [json.loads(s) for s in list_archive.splitlines()]
    assert len(items) == 2
    file1 = items[1]
    assert file1["path"] == "input/file1"
    assert file1["size"] == 81920

    list_archive = cmd(archiver, "list", "test", "--json-lines", "--format={sha256}")
    items = [json.loads(s) for s in list_archive.splitlines()]
    assert len(items) == 2
    file1 = items[1]
    assert file1["path"] == "input/file1"
    assert file1["sha256"] == "b2915eb69f260d8d3c25249195f2c8f4f716ea82ec760ae929732c0262442b2b"


def test_list_depth(archivers, request):
    """Test the --depth option for the list command."""
    archiver = request.getfixturevalue(archivers)

    # Create repository
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Create files at different directory depths
    create_regular_file(archiver.input_path, "file_at_depth_1.txt", size=1)
    create_regular_file(archiver.input_path, "dir1/file_at_depth_2.txt", size=1)
    create_regular_file(archiver.input_path, "dir1/dir2/file_at_depth_3.txt", size=1)

    # Create archive
    cmd(archiver, "create", "test", "input")

    # Test with depth=0 (only the root directory)
    output_depth_0 = cmd(archiver, "list", "test", "--depth=0")
    assert "input" in output_depth_0
    assert "input/file_at_depth_1.txt" not in output_depth_0
    assert "input/dir1" not in output_depth_0
    assert "input/dir1/file_at_depth_2.txt" not in output_depth_0
    assert "input/dir1/dir2" not in output_depth_0
    assert "input/dir1/dir2/file_at_depth_3.txt" not in output_depth_0

    # Test with depth=1 (only input directory and files directly in it)
    output_depth_1 = cmd(archiver, "list", "test", "--depth=1")
    assert "input" in output_depth_1
    assert "input/file_at_depth_1.txt" in output_depth_1
    assert "input/dir1" in output_depth_1
    assert "input/dir1/file_at_depth_2.txt" not in output_depth_1
    assert "input/dir1/dir2" not in output_depth_1
    assert "input/dir1/dir2/file_at_depth_3.txt" not in output_depth_1

    # Test with depth=2 (files up to one level inside input)
    output_depth_2 = cmd(archiver, "list", "test", "--depth=2")
    assert "input" in output_depth_2
    assert "input/file_at_depth_1.txt" in output_depth_2
    assert "input/dir1" in output_depth_2
    assert "input/dir1/file_at_depth_2.txt" in output_depth_2
    assert "input/dir1/dir2" in output_depth_2
    assert "input/dir1/dir2/file_at_depth_3.txt" not in output_depth_2

    # Test with depth=3 (files up to two levels inside input)
    output_depth_3 = cmd(archiver, "list", "test", "--depth=3")
    assert "input" in output_depth_3
    assert "input/file_at_depth_1.txt" in output_depth_3
    assert "input/dir1" in output_depth_3
    assert "input/dir1/file_at_depth_2.txt" in output_depth_3
    assert "input/dir1/dir2" in output_depth_3
    assert "input/dir1/dir2/file_at_depth_3.txt" in output_depth_3

    # Test without depth parameter (should show all files)
    output_no_depth = cmd(archiver, "list", "test")
    assert "input" in output_no_depth
    assert "input/file_at_depth_1.txt" in output_no_depth
    assert "input/dir1" in output_no_depth
    assert "input/dir1/file_at_depth_2.txt" in output_no_depth
    assert "input/dir1/dir2" in output_no_depth
    assert "input/dir1/dir2/file_at_depth_3.txt" in output_no_depth
