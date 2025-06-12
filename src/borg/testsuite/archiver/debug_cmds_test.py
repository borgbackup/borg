import json
import os
import pstats
import sys

import pytest

from ...constants import *  # NOQA
from .. import changedir
from ..compress_test import Compressor
from . import cmd, create_test_files, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


@pytest.mark.skipif(sys.version_info[:3] >= (3, 14, 0), reason="cProfile.Profile broken in Python 3.14.0b2")
def test_debug_profile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input", "--debug-profile=create.prof")
    cmd(archiver, "debug", "convert-profile", "create.prof", "create.pyprof")
    stats = pstats.Stats("create.pyprof")
    stats.strip_dirs()
    stats.sort_stats("cumtime")
    cmd(archiver, "create", "test2", "input", "--debug-profile=create.pyprof")
    stats = pstats.Stats("create.pyprof")  # Only do this on trusted data!
    stats.strip_dirs()
    stats.sort_stats("cumtime")


def test_debug_dump_archive_items(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    with changedir("output"):
        output = cmd(archiver, "debug", "dump-archive-items", "test")
    output_dir = sorted(os.listdir("output"))
    assert len(output_dir) > 0 and output_dir[0].startswith("000000_")
    assert "Done." in output


def test_debug_dump_repo_objs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    with changedir("output"):
        output = cmd(archiver, "debug", "dump-repo-objs")
    output_dir = sorted(os.listdir("output"))
    assert len(output_dir) > 0
    assert "Done." in output


def test_debug_put_get_delete_obj(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    data = b"some data"
    create_regular_file(archiver.input_path, "file", contents=data)

    output = cmd(archiver, "debug", "id-hash", "input/file")
    id_hash = output.strip()

    output = cmd(archiver, "debug", "put-obj", id_hash, "input/file")
    assert id_hash in output

    output = cmd(archiver, "debug", "get-obj", id_hash, "output/file")
    assert id_hash in output

    with open("output/file", "rb") as f:
        data_read = f.read()
    assert data == data_read

    output = cmd(archiver, "debug", "delete-obj", id_hash)
    assert "deleted" in output

    output = cmd(archiver, "debug", "delete-obj", id_hash)
    assert "not found" in output

    output = cmd(archiver, "debug", "delete-obj", "invalid")
    assert "is invalid" in output


def test_debug_id_hash_format_put_get_parse_obj(archivers, request):
    """Test format-obj and parse-obj commands"""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    data = b"some data" * 100
    meta_dict = {"some": "property"}
    meta = json.dumps(meta_dict).encode()
    create_regular_file(archiver.input_path, "plain.bin", contents=data)
    create_regular_file(archiver.input_path, "meta.json", contents=meta)
    output = cmd(archiver, "debug", "id-hash", "input/plain.bin")
    id_hash = output.strip()
    cmd(
        archiver,
        "debug",
        "format-obj",
        id_hash,
        "input/plain.bin",
        "input/meta.json",
        "output/data.bin",
        "--compression=zstd,2",
    )
    output = cmd(archiver, "debug", "put-obj", id_hash, "output/data.bin")
    assert id_hash in output

    output = cmd(archiver, "debug", "get-obj", id_hash, "output/object.bin")
    assert id_hash in output

    cmd(archiver, "debug", "parse-obj", id_hash, "output/object.bin", "output/plain.bin", "output/meta.json")
    with open("output/plain.bin", "rb") as f:
        data_read = f.read()
    assert data == data_read

    with open("output/meta.json") as f:
        meta_read = json.load(f)
    for key, value in meta_dict.items():
        assert meta_read.get(key) == value
    assert meta_read.get("size") == len(data_read)

    c = Compressor(name="zstd", level=2)
    _, data_compressed = c.compress(meta_dict, data=data)
    assert meta_read.get("csize") == len(data_compressed)
    assert meta_read.get("ctype") == c.compressor.ID
    assert meta_read.get("clevel") == c.compressor.level


def test_debug_dump_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    dump_file = archiver.output_path + "/dump"
    output = cmd(archiver, "debug", "dump-manifest", dump_file)
    assert output == ""
    with open(dump_file) as f:
        result = json.load(f)
    assert "archives" in result
    assert "config" in result
    assert "timestamp" in result
    assert "version" in result
    assert "item_keys" in result["config"]
    assert frozenset(result["config"]["item_keys"]) == ITEM_KEYS


def test_debug_dump_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    dump_file = archiver.output_path + "/dump"
    output = cmd(archiver, "debug", "dump-archive", "test", dump_file)
    assert output == ""

    with open(dump_file) as f:
        result = json.load(f)
    assert "_name" in result
    assert "_manifest_entry" in result
    assert "_meta" in result
    assert "_items" in result


def test_debug_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "debug", "info")
    assert "Python" in output
