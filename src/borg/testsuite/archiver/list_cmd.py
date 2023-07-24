import json
import os

from ...constants import *  # NOQA
from . import src_dir, cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_list_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
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
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    output = cmd(archiver, "list", "test", "--format", "{sha256} {path}{NL}")
    assert "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 input/amb" in output
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 input/empty_file" in output


def test_list_chunk_counts(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "empty_file", size=0)
    create_regular_file(archiver.input_path, "two_chunks")
    with open(os.path.join(archiver.input_path, "two_chunks"), "wb") as fd:
        fd.write(b"abba" * 2000000)
        fd.write(b"baab" * 2000000)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    output = cmd(archiver, "list", "test", "--format", "{num_chunks} {unique_chunks} {path}{NL}")
    assert "0 0 input/empty_file" in output
    assert "2 2 input/two_chunks" in output


def test_list_size(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "compressible_file", size=10000)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "-C", "lz4", "test", "input")
    output = cmd(archiver, "list", "test", "--format", "{size} {path}{NL}")
    size, path = output.split("\n")[1].split(" ")
    assert int(size) == 10000


def test_list_json(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
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
