import io
import json
import os
from configparser import ConfigParser

import pytest

from ...constants import *  # NOQA
from ...helpers import bin_to_hex
from . import cmd, create_test_files, RK_ENCRYPTION


def corrupt_archiver(archiver):
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    archiver.cache_path = json.loads(cmd(archiver, "repo-info", "--json"))["cache"].get("path")


def corrupt(file, amount=1):
    with open(file, "r+b") as fd:
        fd.seek(-amount, io.SEEK_END)
        corrupted = bytes(255 - c for c in fd.read(amount))
        fd.seek(-amount, io.SEEK_END)
        fd.write(corrupted)


def test_cache_files(archiver):
    corrupt_archiver(archiver)
    if archiver.cache_path is None:
        pytest.skip("no cache path for this kind of Cache implementation")

    cmd(archiver, "create", "test", "input")
    corrupt(os.path.join(archiver.cache_path, "files"))
    out = cmd(archiver, "create", "test1", "input")
    # borg warns about the corrupt files cache, but then continues without files cache.
    assert "files cache is corrupted" in out


def test_old_version_interfered(archiver):
    corrupt_archiver(archiver)
    if archiver.cache_path is None:
        pytest.skip("no cache path for this kind of Cache implementation")

    # Modify the main manifest ID without touching the manifest ID in the integrity section.
    # This happens if a version without integrity checking modifies the cache.
    config_path = os.path.join(archiver.cache_path, "config")
    config = ConfigParser(interpolation=None)
    config.read(config_path)
    config.set("cache", "manifest", bin_to_hex(bytes(32)))
    with open(config_path, "w") as fd:
        config.write(fd)
    out = cmd(archiver, "repo-info")
    assert "Cache integrity data not available: old Borg version modified the cache." in out
