import shutil
from unittest.mock import patch

import pytest

from ...archive import ChunkBuffer
from ...constants import *  # NOQA
from ...helpers import bin_to_hex
from ...helpers import msgpack
from ...manifest import Manifest
from ...repository import Repository
from . import cmd, src_file, create_src_archive, open_archive, generate_archiver_tests, RK_ENCRYPTION

# Tests that include the 'archivers' argument will generate a tests for each kind of archivers specified.
pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def check_cmd_setup(archiver):
    with patch.object(ChunkBuffer, "BUFFER_SIZE", 10):
        cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
        create_src_archive(archiver, "archive1")
        create_src_archive(archiver, "archive2")


def test_check_usage(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    repo_location = archiver.repository_location

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--progress", exit_code=0)
    assert "Starting repository check" in output
    assert "Starting archive consistency check" in output
    assert "Checking segments" in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--repository-only", exit_code=0)
    assert "Starting repository check" in output
    assert "Starting archive consistency check" not in output
    assert "Checking segments" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", exit_code=0)
    assert "Starting repository check" not in output
    assert "Starting archive consistency check" in output

    output = cmd(
        archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--match-archives=archive2", exit_code=0
    )
    assert "archive1" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--first=1", exit_code=0)
    assert "archive1" in output
    assert "archive2" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--last=1", exit_code=0)
    assert "archive1" not in output
    assert "archive2" in output


def test_date_matching(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path

    shutil.rmtree(repo_path)
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    earliest_ts = "2022-11-20T23:59:59"
    ts_in_between = "2022-12-18T23:59:59"
    create_src_archive(archiver, "archive1", ts=earliest_ts)
    create_src_archive(archiver, "archive2", ts=ts_in_between)
    create_src_archive(archiver, "archive3")
    cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--oldest=23e", exit_code=2)

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--oldest=1m", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--newest=1m", exit_code=0)
    assert "archive3" in output
    assert "archive2" not in output
    assert "archive1" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--newer=1d", exit_code=0)
    assert "archive3" in output
    assert "archive1" not in output
    assert "archive2" not in output

    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--older=1d", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    assert "archive3" not in output

    # check for output when timespan older than the earliest archive is given. Issue #1711
    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--archives-only", "--older=9999m", exit_code=0)
    for archive in ("archive1", "archive2", "archive3"):
        assert archive not in output


def test_missing_file_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)

    archive, repository = open_archive(repo_path, "archive1")

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

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    output = cmd(archiver, f"--repo={repo_location}", "check", "--repair", exit_code=0)
    assert "New missing file chunk detected" in output

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)
    output = cmd(archiver, f"--repo={repo_location}", "list", "archive1", "--format={health}#{path}{NL}", exit_code=0)
    assert "broken#" in output

    # check that the file in the old archives has now a different chunk list without the killed chunk
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(repo_path, archive_name)
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
    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--repair", exit_code=0)
    assert "Healed previously missing file chunk" in output
    assert f"{src_file}: Completely healed previously damaged file!" in output

    # check that the file in the old archives has the correct chunks again
    for archive_name in ("archive1", "archive2"):
        archive, repository = open_archive(repo_path, archive_name)
        with repository:
            for item in archive.iter_items():
                if item.path.endswith(src_file):
                    assert valid_chunks == item.chunks
                    break
            else:
                pytest.fail("should not happen")

    # list is also all-healthy again
    output = cmd(archiver, f"--repo={repo_location}", "list", "archive1", "--format={health}#{path}{NL}", exit_code=0)
    assert "broken#" not in output


def test_missing_archive_item_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        repository.delete(archive.metadata.items[0])
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    cmd(archiver, f"--repo={repo_location}", "check", "--repair", exit_code=0)
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)


def test_missing_archive_metadata(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        repository.delete(archive.id)
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    cmd(archiver, f"--repo={repo_location}", "check", "--repair", exit_code=0)
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)


def test_missing_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        repository.delete(Manifest.MANIFEST_ID)
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)


def test_corrupted_manifest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--repair", exit_code=0)
    assert "archive1" in output
    assert "archive2" in output
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)


def test_manifest_rebuild_corrupted_chunk(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        chunk = repository.get(archive.id)
        corrupted_chunk = chunk + b"corrupted!"
        repository.put(archive.id, corrupted_chunk)
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    output = cmd(archiver, f"--repo={repo_location}", "check", "-v", "--repair", exit_code=0)
    assert "archive2" in output
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)


def test_manifest_rebuild_duplicate_archive(archivers, request):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    archive, repository = open_archive(repo_path, "archive1")
    repo_objs = archive.repo_objs

    with repository:
        manifest = repository.get(Manifest.MANIFEST_ID)
        corrupted_manifest = manifest + b"corrupted!"
        repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
        archive = msgpack.packb(
            {
                "command_line": "",
                "item_ptrs": [],
                "hostname": "foo",
                "username": "bar",
                "name": "archive1",
                "time": "2016-12-15T18:49:51.849711",
                "version": 2,
            }
        )
        archive_id = repo_objs.id_hash(archive)
        repository.put(archive_id, repo_objs.format(archive_id, {}, archive))
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    cmd(archiver, f"--repo={repo_location}", "check", "--repair", exit_code=0)
    output = cmd(archiver, f"--repo={repo_location}", "rlist")
    assert "archive1" in output
    assert "archive1.1" in output
    assert "archive2" in output


def test_extra_chunks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.repository_location.startswith("ssh://__testsuite__"):
        pytest.skip("only works locally")
    repo_location = archiver.repository_location
    check_cmd_setup(archiver)
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)

    with Repository(repo_location, exclusive=True) as repository:
        repository.put(b"01234567890123456789012345678901", b"xxxx")
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
    cmd(archiver, f"--repo={repo_location}", "check", "--repair", exit_code=0)
    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)
    cmd(archiver, f"--repo={repo_location}", "extract", "archive1", "--dry-run", exit_code=0)


@pytest.mark.parametrize("init_args", [["--encryption=repokey-aes-ocb"], ["--encryption", "none"]])
def test_verify_data(archivers, request, init_args):
    archiver = request.getfixturevalue(archivers)
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    check_cmd_setup(archiver)
    shutil.rmtree(repo_path)
    cmd(archiver, f"--repo={repo_location}", "rcreate", *init_args)
    create_src_archive(archiver, "archive1")
    archive, repository = open_archive(repo_path, "archive1")

    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                chunk = item.chunks[-1]
                data = repository.get(chunk.id)
                data = data[0:100] + b"x" + data[101:]
                repository.put(chunk.id, data)
                break
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=0)
    output = cmd(archiver, f"--repo={repo_location}", "check", "--verify-data", exit_code=1)
    assert bin_to_hex(chunk.id) + ", integrity error" in output

    # repair (heal is tested in another test)
    output = cmd(archiver, f"--repo={repo_location}", "check", "--repair", "--verify-data", exit_code=0)
    assert bin_to_hex(chunk.id) + ", integrity error" in output
    assert f"{src_file}: New missing file chunk detected" in output


def test_empty_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.repository_location.startswith("ssh://__testsuite__"):
        pytest.skip("only works locally")
    repo_location = archiver.repository_location
    check_cmd_setup(archiver)

    with Repository(repo_location, exclusive=True) as repository:
        for id_ in repository.list():
            repository.delete(id_)
        repository.commit(compact=False)

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)
