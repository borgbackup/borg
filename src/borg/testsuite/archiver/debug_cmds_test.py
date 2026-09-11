import json
import os
import pstats

import pytest

from ...cache import write_chunkindex_to_repo
from ...constants import *  # NOQA
from ...helpers import bin_to_hex
from ...helpers.passphrase import PassphraseWrong
from ...manifest import Manifest
from .. import changedir
from ..compress_test import Compressor
from . import cmd, create_test_files, create_regular_file, generate_archiver_tests, open_repository
from . import KF_ENCRYPTION, KF_LOCATION, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_debug_profile(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("BORG_DEBUG_PROFILE", "create.prof")
    cmd(archiver, "create", "test", "input")
    # the profile is written by every borg invocation, so switch it off for the conversion -
    # it reads the profile we just wrote and would otherwise overwrite it while doing so.
    monkeypatch.delenv("BORG_DEBUG_PROFILE")
    cmd(archiver, "debug", "convert-profile", "create.prof", "create.pyprof")
    stats = pstats.Stats("create.pyprof")
    stats.strip_dirs()
    stats.sort_stats("cumtime")
    monkeypatch.setenv("BORG_DEBUG_PROFILE", "create.pyprof")
    cmd(archiver, "create", "test2", "input")
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
    # put-obj stored the file's bytes, not a repo object, so the key type is read from the manifest.
    assert "Could not set up the key" not in output

    # the object is gone now: deleting it again reports it is not there
    output = cmd(archiver, "debug", "delete-obj", id_hash)
    assert "not found" in output

    output = cmd(archiver, "debug", "delete-obj", "invalid")
    assert "is invalid" in output


def put_pack_with_superseded_gap(archiver):
    """Store objects W, X and Y in one pack and X again in a second pack, then write the chunks index.

    The index maps X to the second pack, so X's copy in the first pack is a superseded duplicate.
    Returns ((w_id, x_id, y_id), (w_size, x_size, y_size)), the object sizes in the first pack.
    """
    with open_repository(archiver) as repository:
        repo_objs = Manifest.load(repository, Manifest.NO_OPERATION_CHECK).repo_objs
        datas = (b"W" * 100, b"X" * 100, b"Y" * 100)
        ids = tuple(repo_objs.id_hash(data) for data in datas)
        objs = [repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM) for id, data in zip(ids, datas)]
        for id, obj in zip(ids, objs):
            repository.put(id, obj)
        repository.flush()
        pack_id = repository.chunks[ids[0]].pack_id
        assert all(repository.chunks[id].pack_id == pack_id for id in ids)
        sizes = tuple(repository.chunks[id].obj_size for id in ids)
        repository.put(ids[1], objs[1])  # the index now points X at this second copy
        repository.flush()
        assert repository.chunks[ids[1]].pack_id != pack_id
        write_chunkindex_to_repo(repository, repository.chunks, incremental=False, force_write=True, delete_other=True)
    return ids, sizes


def pack_size_of(archiver, id):
    with open_repository(archiver) as repository:
        pack_name = bin_to_hex(repository.chunks[id].pack_id)
        return next(info.size for info in repository.store_list("packs") if info.name == pack_name)


def test_debug_delete_obj_drops_superseded_gap(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    (w_id, x_id, y_id), (_, _, y_size) = put_pack_with_superseded_gap(archiver)

    output = cmd(archiver, "debug", "delete-obj", bin_to_hex(w_id))

    assert "deleted" in output
    assert "Could not set up the key" not in output
    assert pack_size_of(archiver, y_id) == y_size  # W and the superseded copy of X are gone
    with open_repository(archiver) as repository:
        assert repository.get(w_id, raise_missing=False) is None
        assert repository.get(x_id) is not None  # served from its second copy


def test_debug_delete_obj_without_a_key_keeps_superseded_gap(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    (w_id, x_id, y_id), (_, x_size, y_size) = put_pack_with_superseded_gap(archiver)
    for name in os.listdir(archiver.keys_path):
        os.unlink(os.path.join(archiver.keys_path, name))

    output = cmd(archiver, "debug", "delete-obj", bin_to_hex(w_id))

    assert "Could not set up the key" in output
    assert "deleted" in output
    assert pack_size_of(archiver, y_id) == x_size + y_size  # only W is gone, the gap is kept


def test_debug_delete_obj_with_a_wrong_passphrase_deletes_nothing(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    (w_id, x_id, y_id), (w_size, x_size, y_size) = put_pack_with_superseded_gap(archiver)
    monkeypatch.setenv("BORG_PASSPHRASE", "wrong")

    if archiver.FORK_DEFAULT:
        cmd(archiver, "debug", "delete-obj", bin_to_hex(w_id), exit_code=PassphraseWrong.exit_mcode)
    else:
        with pytest.raises(PassphraseWrong):
            cmd(archiver, "debug", "delete-obj", bin_to_hex(w_id))

    assert pack_size_of(archiver, y_id) == w_size + x_size + y_size
    with open_repository(archiver) as repository:
        assert repository.get(w_id, raise_missing=False) is not None


def test_debug_delete_obj_with_invalid_ids_only_sets_up_no_key(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("BORG_PASSPHRASE", "wrong")

    output = cmd(archiver, "debug", "delete-obj", "invalid")

    assert "is invalid" in output
    assert "Could not set up the key" not in output


def test_debug_id_hash_format_put_get_parse_obj(archivers, request):
    """Test format-obj and parse-obj commands."""
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


def test_debug_format_obj_respects_type(archivers, request):
    """Test format-obj uses the type from metadata JSON, not just ROBJ_FILE_STREAM."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    data = b"some data" * 100
    meta_dict = {"some": "property", "type": ROBJ_ARCHIVE_STREAM}
    meta = json.dumps(meta_dict).encode()
    create_regular_file(archiver.input_path, "data.bin", contents=data)
    create_regular_file(archiver.input_path, "meta.json", contents=meta)
    output = cmd(archiver, "debug", "id-hash", "input/data.bin")
    id_hash = output.strip()
    cmd(archiver, "debug", "format-obj", id_hash, "input/data.bin", "input/meta.json", "input/repoobj.bin")
    output = cmd(archiver, "debug", "put-obj", id_hash, "input/repoobj.bin")
    assert id_hash in output
    output = cmd(archiver, "debug", "get-obj", id_hash, "output/object.bin")
    assert id_hash in output
    cmd(archiver, "debug", "parse-obj", id_hash, "output/object.bin", "output/data.bin", "output/meta.json")
    with open("output/meta.json") as f:
        meta_read = json.load(f)
    assert meta_read["type"] == ROBJ_ARCHIVE_STREAM


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
