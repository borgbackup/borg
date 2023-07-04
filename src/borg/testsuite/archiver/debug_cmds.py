import json
import os
import pstats

from ...constants import *  # NOQA
from .. import changedir
from ..compress import Compressor
from . import cmd, create_test_files, create_regular_file, RK_ENCRYPTION


def pytest_generate_tests(metafunc):
    # Generates tests that run on local and remote repos, as well as with a binary base.
    if "archivers" in metafunc.fixturenames:
        metafunc.parametrize("archivers", ["archiver", "remote_archiver", "binary_archiver"])


def test_debug_profile(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_test_files(input_path)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input", "--debug-profile=create.prof")
    cmd(archiver, "debug", "convert-profile", "create.prof", "create.pyprof")
    stats = pstats.Stats("create.pyprof")
    stats.strip_dirs()
    stats.sort_stats("cumtime")
    cmd(archiver, f"--repo={repo_location}", "create", "test2", "input", "--debug-profile=create.pyprof")
    stats = pstats.Stats("create.pyprof")  # Only do this on trusted data!
    stats.strip_dirs()
    stats.sort_stats("cumtime")


def test_debug_dump_archive_items(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_test_files(input_path)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    with changedir("output"):
        output = cmd(archiver, f"--repo={repo_location}", "debug", "dump-archive-items", "test")
    output_dir = sorted(os.listdir("output"))
    assert len(output_dir) > 0 and output_dir[0].startswith("000000_")
    assert "Done." in output


def test_debug_dump_repo_objs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_test_files(input_path)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    with changedir("output"):
        output = cmd(archiver, f"--repo={repo_location}", "debug", "dump-repo-objs")
    output_dir = sorted(os.listdir("output"))
    assert len(output_dir) > 0 and output_dir[0].startswith("00000000_")
    assert "Done." in output


def test_debug_put_get_delete_obj(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    data = b"some data"
    create_regular_file(input_path, "file", contents=data)
    output = cmd(archiver, f"--repo={repo_location}", "debug", "id-hash", "input/file")
    id_hash = output.strip()
    output = cmd(archiver, f"--repo={repo_location}", "debug", "put-obj", id_hash, "input/file")
    assert id_hash in output
    output = cmd(archiver, f"--repo={repo_location}", "debug", "get-obj", id_hash, "output/file")
    assert id_hash in output
    with open("output/file", "rb") as f:
        data_read = f.read()
    assert data == data_read
    output = cmd(archiver, f"--repo={repo_location}", "debug", "delete-obj", id_hash)
    assert "deleted" in output
    output = cmd(archiver, f"--repo={repo_location}", "debug", "delete-obj", id_hash)
    assert "not found" in output
    output = cmd(archiver, f"--repo={repo_location}", "debug", "delete-obj", "invalid")
    assert "is invalid" in output


def test_debug_id_hash_format_put_get_parse_obj(archivers, request):
    """Test format-obj and parse-obj commands"""
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path

    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    data = b"some data" * 100
    meta_dict = {"some": "property"}
    meta = json.dumps(meta_dict).encode()
    create_regular_file(input_path, "plain.bin", contents=data)
    create_regular_file(input_path, "meta.json", contents=meta)

    output = cmd(archiver, f"--repo={repo_location}", "debug", "id-hash", "input/plain.bin")
    id_hash = output.strip()

    cmd(
        archiver,
        f"--repo={repo_location}",
        "debug",
        "format-obj",
        id_hash,
        "input/plain.bin",
        "input/meta.json",
        "output/data.bin",
        "--compression=zstd,2",
    )

    output = cmd(archiver, f"--repo={repo_location}", "debug", "put-obj", id_hash, "output/data.bin")
    assert id_hash in output

    output = cmd(archiver, f"--repo={repo_location}", "debug", "get-obj", id_hash, "output/object.bin")
    assert id_hash in output

    cmd(
        archiver,
        f"--repo={repo_location}",
        "debug",
        "parse-obj",
        id_hash,
        "output/object.bin",
        "output/plain.bin",
        "output/meta.json",
    )

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
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    dump_file = archiver.output_path + "/dump"
    output = cmd(archiver, f"--repo={repo_location}", "debug", "dump-manifest", dump_file)
    assert output == ""
    with open(dump_file) as f:
        result = json.load(f)
    assert "archives" in result
    assert "config" in result
    assert "item_keys" in result
    assert "timestamp" in result
    assert "version" in result


def test_debug_dump_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, input_path = archiver.repository_location, archiver.input_path
    create_regular_file(input_path, "file1", size=1024 * 80)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    dump_file = archiver.output_path + "/dump"
    output = cmd(archiver, f"--repo={repo_location}", "debug", "dump-archive", "test", dump_file)
    assert output == ""
    with open(dump_file) as f:
        result = json.load(f)
    assert "_name" in result
    assert "_manifest_entry" in result
    assert "_meta" in result
    assert "_items" in result


def test_debug_refcount_obj(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location = archiver.repository_location
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    output = cmd(archiver, f"--repo={repo_location}", "debug", "refcount-obj", "0" * 64).strip()
    assert (
        output
        == "object 0000000000000000000000000000000000000000000000000000000000000000 not found [info from chunks cache]."
    )

    create_json = json.loads(cmd(archiver, f"--repo={repo_location}", "create", "--json", "test", "input"))
    archive_id = create_json["archive"]["id"]
    output = cmd(archiver, f"--repo={repo_location}", "debug", "refcount-obj", archive_id).strip()
    assert output == "object " + archive_id + " has 1 referrers [info from chunks cache]."

    # Invalid IDs do not abort or return an error
    output = cmd(archiver, f"--repo={repo_location}", "debug", "refcount-obj", "124", "xyza").strip()
    assert output == "object id 124 is invalid." + os.linesep + "object id xyza is invalid."


def test_debug_info(archivers, request):
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "debug", "info")
    assert "Python" in output
