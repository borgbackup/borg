import io
import json
import os
from configparser import ConfigParser

import pytest

from ...constants import *  # NOQA
from ...crypto.file_integrity import FileIntegrityError
from ...helpers import bin_to_hex


def test_check_corrupted_repository(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test", "--dry-run")
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "check")

    name = sorted(os.listdir(os.path.join(archiver_setup.tmpdir, "repository", "data", "0")), reverse=True)[1]
    with open(os.path.join(archiver_setup.tmpdir, "repository", "data", "0", name), "r+b") as fd:
        fd.seek(100)
        fd.write(b"XXXX")

    cmd_fixture(f"--repo={archiver_setup.repository_location}", "check", exit_code=1)


@pytest.fixture()
def corrupted_archiver(archiver_setup, cmd_fixture, create_test_files):
    create_test_files()
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    archiver_setup.cache_path = json.loads(
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rinfo", "--json")
    )["cache"]["path"]
    yield archiver_setup


def corrupt(file, amount=1):
    with open(file, "r+b") as fd:
        fd.seek(-amount, io.SEEK_END)
        corrupted = bytes(255 - c for c in fd.read(amount))
        fd.seek(-amount, io.SEEK_END)
        fd.write(corrupted)


def test_cache_chunks(corrupted_archiver, cmd_fixture):
    corrupt(os.path.join(corrupted_archiver.cache_path, "chunks"))
    if corrupted_archiver.FORK_DEFAULT:
        out = cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rinfo", exit_code=2)
        assert "failed integrity check" in out
    else:
        with pytest.raises(FileIntegrityError):
            cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rinfo")


def test_cache_files(corrupted_archiver, cmd_fixture):
    cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "create", "test", "input")
    corrupt(os.path.join(corrupted_archiver.cache_path, "files"))
    out = cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "create", "test1", "input")
    # borg warns about the corrupt files cache, but then continues without files cache.
    assert "files cache is corrupted" in out


def test_chunks_archive(corrupted_archiver, cmd_fixture):
    cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "create", "test1", "input")
    # Find ID of test1 such that we can corrupt it later :)
    target_id = cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rlist", "--format={id}{NL}").strip()
    cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "create", "test2", "input")

    # Force cache sync, creating archive chunks of test1 and test2 in chunks.archive.d
    cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rdelete", "--cache-only")
    cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rinfo", "--json")

    chunks_archive = os.path.join(corrupted_archiver.cache_path, "chunks.archive.d")
    assert len(os.listdir(chunks_archive)) == 4  # two archives, one chunks cache and one .integrity file each

    corrupt(os.path.join(chunks_archive, target_id + ".compact"))

    # Trigger cache sync by changing the manifest ID in the cache config
    config_path = os.path.join(corrupted_archiver.cache_path, "config")
    config = ConfigParser(interpolation=None)
    config.read(config_path)
    config.set("cache", "manifest", bin_to_hex(bytes(32)))
    with open(config_path, "w") as fd:
        config.write(fd)

    # Cache sync notices corrupted archive chunks, but automatically recovers.
    out = cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "create", "-v", "test3", "input", exit_code=1)
    assert "Reading cached archive chunk index for test1" in out
    assert "Cached archive chunk index of test1 is corrupted" in out
    assert "Fetching and building archive index for test1" in out


def test_old_version_interfered(corrupted_archiver, cmd_fixture):
    # Modify the main manifest ID without touching the manifest ID in the integrity section.
    # This happens if a version without integrity checking modifies the cache.
    config_path = os.path.join(corrupted_archiver.cache_path, "config")
    config = ConfigParser(interpolation=None)
    config.read(config_path)
    config.set("cache", "manifest", bin_to_hex(bytes(32)))
    with open(config_path, "w") as fd:
        config.write(fd)

    out = cmd_fixture(f"--repo={corrupted_archiver.repository_location}", "rinfo")
    assert "Cache integrity data not available: old Borg version modified the cache." in out
