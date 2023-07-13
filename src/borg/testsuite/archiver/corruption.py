import io
import json
import os
from configparser import ConfigParser

import pytest

from ...constants import *  # NOQA
from ...crypto.file_integrity import FileIntegrityError
from ...helpers import bin_to_hex
from . import cmd, create_src_archive, create_test_files, RK_ENCRYPTION


def test_check_corrupted_repository(archiver):
    repo_location, tmpdir = archiver.repository_location, archiver.tmpdir
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    cmd(archiver, f"--repo={repo_location}", "extract", "test", "--dry-run")
    cmd(archiver, f"--repo={repo_location}", "check")

    name = sorted(os.listdir(os.path.join(tmpdir, "repository", "data", "0")), reverse=True)[1]
    with open(os.path.join(tmpdir, "repository", "data", "0", name), "r+b") as fd:
        fd.seek(100)
        fd.write(b"XXXX")

    cmd(archiver, f"--repo={repo_location}", "check", exit_code=1)


def corrupt_archiver(archiver):
    create_test_files(archiver.input_path)
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    archiver.cache_path = json.loads(cmd(archiver, f"--repo={archiver.repository_location}", "rinfo", "--json"))[
        "cache"
    ]["path"]


def corrupt(file, amount=1):
    with open(file, "r+b") as fd:
        fd.seek(-amount, io.SEEK_END)
        corrupted = bytes(255 - c for c in fd.read(amount))
        fd.seek(-amount, io.SEEK_END)
        fd.write(corrupted)


def test_cache_chunks(archiver):
    corrupt_archiver(archiver)
    repo_location, cache_path = archiver.repository_location, archiver.cache_path
    corrupt(os.path.join(cache_path, "chunks"))
    if archiver.FORK_DEFAULT:
        out = cmd(archiver, f"--repo={repo_location}", "rinfo", exit_code=2)
        assert "failed integrity check" in out
    else:
        with pytest.raises(FileIntegrityError):
            cmd(archiver, f"--repo={repo_location}", "rinfo")


def test_cache_files(archiver):
    corrupt_archiver(archiver)
    repo_location, cache_path = archiver.repository_location, archiver.cache_path
    cmd(archiver, f"--repo={repo_location}", "create", "test", "input")
    corrupt(os.path.join(cache_path, "files"))
    out = cmd(archiver, f"--repo={repo_location}", "create", "test1", "input")
    # borg warns about the corrupt files cache, but then continues without files cache.
    assert "files cache is corrupted" in out


def test_chunks_archive(archiver):
    corrupt_archiver(archiver)
    repo_location, cache_path = archiver.repository_location, archiver.cache_path
    cmd(archiver, f"--repo={repo_location}", "create", "test1", "input")
    # Find ID of test1, so we can corrupt it later :)
    target_id = cmd(archiver, f"--repo={repo_location}", "rlist", "--format={id}{NL}").strip()
    cmd(archiver, f"--repo={repo_location}", "create", "test2", "input")

    # Force cache sync, creating archive chunks of test1 and test2 in chunks.archive.d
    cmd(archiver, f"--repo={repo_location}", "rdelete", "--cache-only")
    cmd(archiver, f"--repo={repo_location}", "rinfo", "--json")

    chunks_archive = os.path.join(cache_path, "chunks.archive.d")
    assert len(os.listdir(chunks_archive)) == 4  # two archives, one chunks cache and one .integrity file each

    corrupt(os.path.join(chunks_archive, target_id + ".compact"))

    # Trigger cache sync by changing the manifest ID in the cache config
    config_path = os.path.join(cache_path, "config")
    config = ConfigParser(interpolation=None)
    config.read(config_path)
    config.set("cache", "manifest", bin_to_hex(bytes(32)))
    with open(config_path, "w") as fd:
        config.write(fd)

    # Cache sync notices corrupted archive chunks, but automatically recovers.
    out = cmd(archiver, f"--repo={repo_location}", "create", "-v", "test3", "input", exit_code=1)
    assert "Reading cached archive chunk index for test1" in out
    assert "Cached archive chunk index of test1 is corrupted" in out
    assert "Fetching and building archive index for test1" in out


def test_old_version_interfered(archiver):
    corrupt_archiver(archiver)
    # Modify the main manifest ID without touching the manifest ID in the integrity section.
    # This happens if a version without integrity checking modifies the cache.
    repo_location, cache_path = archiver.repository_location, archiver.cache_path
    config_path = os.path.join(cache_path, "config")
    config = ConfigParser(interpolation=None)
    config.read(config_path)
    config.set("cache", "manifest", bin_to_hex(bytes(32)))
    with open(config_path, "w") as fd:
        config.write(fd)
    out = cmd(archiver, f"--repo={repo_location}", "rinfo")
    assert "Cache integrity data not available: old Borg version modified the cache." in out
