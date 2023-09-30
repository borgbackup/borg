from datetime import datetime, timezone, timedelta
import shutil
from unittest.mock import patch

import pytest

from ...archive import ChunkBuffer
from ...constants import *  # NOQA
from ...helpers import bin_to_hex, msgpack
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, src_file, create_src_archive, open_archive, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def check_cmd_setup(archiver):
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        cmd(archiver, "rcreate", RK_ENCRYPTION)
        create_src_archive(archiver, "archive1")
        create_src_archive(archiver, "archive2")


def test_check_usage(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)

    output = cmd(archiver, "check", "-v", "--progress", exit_code=0)
    assert "Starting repository check" in output
    assert "Starting archive consistency check" in output
    assert "Checking segments" in output

    output = cmd(archiver, "check", "-v", "--repository-only", exit_code=0)
    assert "Starting repository check" in output
    assert "Starting archive consistency check" not in output
    assert "Checking segments" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", exit_code=0)
    assert "Starting repository check" not in output
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
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    earliest_ts = "2022-11-20T23:59:59"
    ts_in_between = "2022-12-18T23:59:59"
    create_src_archive(archiver, "archive1", ts=earliest_ts)
    create_src_archive(archiver, "archive2", ts=ts_in_between)
    create_src_archive(archiver, "archive3")
    cmd(archiver, "check", "-v", "--archives-only", "--oldest=23e", exit_code=2)

    output = cmd(archiver, "check", "-v", "--archives-only", "--oldest=1m", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newest=1m", exit_code=0)
    assert "archive3" in output
    assert "archive2" not in output
    assert "archive1" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--newer=1d", exit_code=0)
    assert "archive3" in output
    assert "archive1" not in output
    assert "archive2" not in output

    output = cmd(archiver, "check", "-v", "--archives-only", "--older=1d", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output

    # check for output when timespan older than the earliest archive is given. Issue #1711
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
        repository.commit(compact=False)

    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "--repair", exit_code=0)
    assert "New missing file chunk detected" in output

    cmd(archiver, "check", exit_code=0)
    output = cmd(archiver, "list", "archive1", "--format={health}#{path}{NL}", exit_code=0)
    assert "broken#" in output

    # check that the file in the old archives has now a different chunk list without the killed chunk
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(archiver.repository_path, archive_name)
        with repository:
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    assert valid_chunks != item.chunks
                    assert killed_chunk not in item.chunks
                    break
            else:
                pytest.fail("should not happen")  # convert 'fail'

    # do a fresh backup (that will include the killed chunk)
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        create_src_archive(archiver, "archive3")

    # check should be able to heal the file now:
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "Healed previously missing file chunk" in output
    assert f"{src_file}: Completely healed previously damaged file!" in output

    # check that the file in the old archives has the correct chunks again
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(archiver.repository_path, archive_name)
        with repository:
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    assert valid_chunks == item.chunks
                    break
            else:
                pytest.fail("should not happen")

    # list is also all-healthy again
    output = cmd(archiver, "list", "archive1", "--format={health}#{path}{NL}", exit_code=0)
    assert "broken#" not in output


def test_missing_archive_item_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.metadata.items[0])
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_archive_metadata(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(archive.id)
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)


def test_missing_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        repository.delete(Manifest.MANIFEST_ID)
        repository.commit(compact=False)
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
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        repository.commit(compact=False)
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
        repository.put(Manifest.MANIFEST_ID, cdata)
        repository.commit(compact=False)
    # borg should notice that the manifest has the wrong ro_type.
    cmd(archiver, "check", exit_code=1)
    # borg check --repair should remove the corrupted manifest and rebuild a new one.
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_manifest_rebuild_corrupted_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        chunk = repository.get(archive.id)
        corrupted_chunk = chunk + b"corrupted!"
        repository.put(archive.id, corrupted_chunk)
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    output = cmd(archiver, "check", "-v", "--repair", exit_code=0)
    assert "archive2" in output
    cmd(archiver, "check", exit_code=0)


def test_manifest_rebuild_duplicate_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    repo_objs = archive.repo_objs
    with repository:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        archive_dict = {
            "command_line": "",
            "item_ptrs": [],
            "hostname": "foo",
            "username": "bar",
            "name": "archive1",
            "time": "2016-12-15T18:49:51.849711",
            "version": 2,
        }
        archive = repo_objs.key.pack_metadata(archive_dict)
        archive_id = repo_objs.id_hash(archive)
        repository.put(archive_id, repo_objs.format(archive_id, {}, archive, ro_type=ROBJ_ARCHIVE_META))
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    output = cmd(archiver, "rlist")
    assert "archive1" in output
    assert "archive1.1" in output
    assert "archive2" in output


def test_spoofed_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    repo_objs = archive.repo_objs
    with repository:
        # attacker would corrupt or delete the manifest to trigger a rebuild of it:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
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
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", "--debug", exit_code=0)
    output = cmd(archiver, "rlist")
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
        repository.put(b"01234567890123456789012345678901", b"xxxx")
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", exit_code=1)
    cmd(archiver, "check", "--repair", exit_code=0)
    cmd(archiver, "check", exit_code=0)
    cmd(archiver, "extract", "archive1", "--dry-run", exit_code=0)


@pytest.mark.parametrize("init_args", [["--encryption=repokey-aes-ocb"], ["--encryption", "none"]])
def test_verify_data(archivers, request, init_args):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "rcreate", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                data = repository.get(chunk.id)
                data = data[0:100] + b"x" + data[101:]
                repository.put(chunk.id, data)
                break
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=0)
    output = cmd(archiver, "check", "--verify-data", exit_code=1)
    assert bin_to_hex(chunk.id) + ", integrity error" in output

    # repair (heal is tested in another test)
    output = cmd(archiver, "check", "--repair", "--verify-data", exit_code=0)
    assert bin_to_hex(chunk.id) + ", integrity error" in output
    assert f"{src_file}: New missing file chunk detected" in output


def test_empty_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() == "remote":
        pytest.skip("only works locally")
    check_cmd_setup(archiver)
    with Repository(archiver.repository_location, exclusive=True) as repository:
        for id_ in repository.list():
            repository.delete(id_)
        repository.commit(compact=False)
    cmd(archiver, "check", exit_code=1)
