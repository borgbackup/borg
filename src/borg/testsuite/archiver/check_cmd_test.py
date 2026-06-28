from datetime import datetime, timezone, timedelta
from pathlib import Path
import shutil
from unittest.mock import patch

import pytest

from ...archive import ChunkBuffer
from ...constants import *  # NOQA
from ...helpers import bin_to_hex, msgpack
from ...manifest import Manifest
from ...repository import Repository
from ..repository_test import fchunk, corrupt_chunk_on_disk
from . import cmd, src_file, create_src_archive, open_archive, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def corrupt(data, position):
    """Return data with the byte at position flipped, so the result is guaranteed to differ.

    Overwriting a byte with a fixed value is not reliable: if the original byte already happens
    to have that value, nothing changes and the "corruption" is a no-op. For encrypted/MACed
    objects the bytes are ~random, so a fixed overwrite is a no-op ~1/256 of the time, which made
    tests relying on it intermittently fail. Flipping all bits always changes the byte.
    """
    if position < 0:
        position += len(data)
    return data[:position] + bytes([data[position] ^ 0xFF]) + data[position + 1 :]


def check_cmd_setup(archiver):
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        cmd(archiver, "repo-create", RK_ENCRYPTION)
        create_src_archive(archiver, "archive1")
        create_src_archive(archiver, "archive2")


def test_check_usage(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    output = cmd(archiver, "check", "-v", "--progress", exit_code=0)
    assert "Starting full repository check" in output
    assert "Starting archive consistency check" in output

    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=0)
    assert "Starting full repository check" in output
    assert "Starting archive consistency check" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", exit_code=0)
    assert "Starting full repository check" not in output
    assert "Starting archive consistency check" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--match-archives=archive2", exit_code=0)
    assert "archive1" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--first=1", exit_code=0)
    assert "archive1" in output
    assert "archive2" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--last=1", exit_code=0)
    assert "archive1" not in output
    assert "archive2" in output


def test_date_matching(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-2022-11-20", ts="2022-11-20T23:59:59")
    create_src_archive(archiver, "archive-2022-12-18", ts="2022-12-18T23:59:59")
    create_src_archive(archiver, "archive-now")
    cmd(archiver, "check", "-v", "--archives-only", "--oldest=23e", exit_code=2)

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=1y", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=1y", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=1m", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=1m", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=4w", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=4w", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=1d", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=1d", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=24H", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=24H", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=1440M", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=1440M", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=86400S", exit_code=0)
    assert "archive-2022-11-20" not in output
    assert "archive-2022-12-18" not in output
    assert "archive-now" in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=86400S", exit_code=0)
    assert "archive-2022-11-20" in output
    assert "archive-2022-12-18" in output
    assert "archive-now" not in output

    # Check for output when a time span older than the earliest archive is given. Issue #1711
    output = cmd(archiver, "check", "-v", "--archives-only", "--older=9999m", exit_code=0)
    for archive in ("archive1", "archive2", "archive3"):
        assert archive not in output


def test_missing_file_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    archive, repository = open_archive(archiver.repository_path, "archive1")

    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                valid_chunks = item.chunks
                killed_chunk = valid_chunks[-1]
                repository.delete(killed_chunk.id)
                break
        else:
            pytest.fail("should not happen")  # convert 'fail'

    output = cmd(archiver, "check", exit_code=1)
    assert "Missing file chunk detected" in output
    output = cmd(archiver, "check", "--repair", exit_code=0)
    assert "Missing file chunk detected" in output  # repair is not changing anything, just reporting.

    # check does not modify the chunks list.
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(archiver.repository_path, archive_name)
        with repository:
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    assert len(valid_chunks) == len(item.chunks)
                    assert valid_chunks == item.chunks
                    break
            else:
                pytest.fail("should not happen")  # convert 'fail'

    # do a fresh backup (that will include the killed chunk)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        create_src_archive(archiver, "archive3")

    # check should not complain anymore about missing chunks:
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "Missing file chunk detected" not in output


def test_missing_archive_item_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.metadata.items[0])
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_archive_metadata(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.id)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        if isinstance(repository, Repository):
            repository.store_delete("config/manifest")
        else:
            repository.delete(Manifest.MANIFEST_ID)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_corrupted_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = repository.get_manifest()
        corrupted_manifest = corrupt(manifest, 250)
        repository.put_manifest(corrupted_manifest)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_spoofed_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        cdata = manifest.repo_objs.format(
            Manifest.MANIFEST_ID,
            {},
            msgpack.packb(
                {
                    "version": 1,
                    "archives": {},
                    "config": {},
                    "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(timespec="microseconds"),
                }
            ),
            # we assume that an attacker can put a file into backup src files that contains a fake manifest.
            # but, the attacker can not influence the ro_type borg will use to store user file data:
            ro_type=ROBJ_FILE_STREAM,  # a real manifest is stored with ROBJ_MANIFEST
        )
        # maybe a repo-side attacker could manage to move the fake manifest file chunk over to the manifest ID.
        # we simulate this here by directly writing the fake manifest data to the manifest ID.
        repository.put_manifest(cdata)
    # borg should notice that the manifest has the wrong ro_type.
    cmd(archiver, "check", exit_code=1)
    # borg check --repair should remove the corrupted manifest and rebuild a new one.
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


@pytest.mark.skip(reason="TODO: repair does not yet rewrite store-corrupted packs, refs #8572")
def test_manifest_rebuild_corrupted_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = repository.get_manifest()
        corrupted_manifest = corrupt(manifest, 250)
        repository.put_manifest(corrupted_manifest)
        corrupt_chunk_on_disk(repository, archive.id)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" not in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_check_undelete_archives(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)  # creates archive1 and archive2
    existing_archive_ids = set(cmd(archiver, "repo-list", "--short").splitlines())
    create_src_archive(archiver, "archive3")
    archive_ids = set(cmd(archiver, "repo-list", "--short").splitlines())
    new_archive_id_hex = (archive_ids - existing_archive_ids).pop()
    (Path(archiver.repository_path) / "archives" / new_archive_id_hex).unlink()  # lose the entry for archive3
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output
    # borg check will re-discover archive3 and create a new archives directory entry.
    cmd(archiver, "check", "--repair", "--find-lost-archives", exit_code=0)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" in output


def test_spoofed_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    repo_objs = archive.repo_objs
    with repository:
        # attacker would corrupt or delete the manifest to trigger a rebuild of it:
        manifest = repository.get_manifest()
        corrupted_manifest = corrupt(manifest, 250)
        repository.put_manifest(corrupted_manifest)
        archive_dict = {
            "command_line": "",
            "item_ptrs": [],
            "hostname": "foo",
            "username": "bar",
            "name": "archive_spoofed",
            "time": "2016-12-15T18:49:51.849711",
            "version": 2,
        }
        archive = repo_objs.key.pack_metadata(archive_dict)
        archive_id = repo_objs.id_hash(archive)
        repository.put(
            archive_id,
            repo_objs.format(
                archive_id,
                {},
                archive,
                # we assume that an attacker can put a file into backup src files that contains a fake archive.
                # but, the attacker can not influence the ro_type borg will use to store user file data:
                ro_type=ROBJ_FILE_STREAM,  # a real archive is stored with ROBJ_ARCHIVE_META
            ),
        )
        repository.flush()  # make the put durable before close()/the check below
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", "--debug", exit_code=0)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" in output
    assert "archive_spoofed" not in output


def test_extra_chunks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    cmd(archiver, "check", exit_code=0)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        key = b"01234567890123456789012345678901"
        chunk = fchunk(b"xxxx", chunk_id=key)
        repository.put(key, chunk)
        repository.flush()  # make the put durable before close()/the check below
    cmd(archiver, "check", "-v", exit_code=0)  # check does not deal with orphans anymore


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "none"]])
def test_verify_data(archivers, request, init_args):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("only works locally, patches objects")

    check_cmd_setup(archiver)
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                corrupt_chunk_on_disk(repository, chunk.id)
                break

    # the normal archives check does not read file content data.
    cmd(archiver, "check", "--archives-only", exit_code=0)
    # but with --verify-data, it does and notices the issue.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output

    # repair will find the defect chunk and remove it
    output = cmd(archiver, "check", "--repair", "--verify-data", exit_code=0)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert f"{src_file}: Missing file chunk detected" in output

    # run with --verify-data again, it will notice the missing chunk.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{src_file}: Missing file chunk detected" in output


@pytest.mark.parametrize("init_args", [["--encryption=aes256-ocb"], ["--encryption", "none"]])
def test_corrupted_file_chunk(archivers, request, init_args):
    ## like test_verify_data, but also checks a repository-only check passes after repair and a plain
    ## archives check reports the missing chunk.

    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                corrupt_chunk_on_disk(repository, chunk.id)
                break

    # --verify-data decrypts and catches the corruption.
    output = cmd(archiver, "check", "--archives-only", "--verify-data", exit_code=1)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output

    # repair: the defect chunk will be removed.
    output = cmd(archiver, "check", "--repair", "--verify-data", exit_code=0)
    assert f"{bin_to_hex(chunk.id)}, integrity error" in output
    assert f"{src_file}: Missing file chunk detected" in output

    # run normal check again
    cmd(archiver, "check", "--repository-only", exit_code=0)
    output = cmd(archiver, "check", "--archives-only", exit_code=1)
    assert f"{src_file}: Missing file chunk detected" in output


@pytest.mark.skip(
    reason="TODO: a non-repair check verifies index and packs by sha256 and uses that verified index (it does "
    "not rebuild it); after dropping all packs the index still lists their chunks, so reading them raises "
    "ObjectNotFound instead of being reported as missing. Needs the index/repair redesign, refs #8572."
)
def test_empty_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        # empty the repo by dropping every pack file directly via the store. We iterate the actual
        # packs/ listing (the file names are the pack_ids), so this does not depend on what list()
        # yields.
        for info in repository.store_list("packs"):
            repository.store_delete("packs/" + info.name)
    cmd(archiver, "check", exit_code=1)
