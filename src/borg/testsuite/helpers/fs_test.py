import errno
import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from ...constants import *  # NOQA
from ...constants import CACHE_TAG_NAME, CACHE_TAG_CONTENTS
from ...helpers.fs import (
    dir_is_tagged,
    get_base_dir,
    get_cache_dir,
    get_keys_dir,
    get_security_dir,
    get_config_dir,
    get_runtime_dir,
    dash_open,
    safe_unlink,
    remove_dotdot_prefixes,
    make_path_safe,
)
from ...platform import is_win32, is_darwin
from .. import are_hardlinks_supported
from .. import rejected_dotdot_paths


def test_get_base_dir(monkeypatch):
    """test that get_base_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("USER", raising=False)
    assert get_base_dir(legacy=True) == os.path.expanduser("~")
    monkeypatch.setenv("USER", "root")
    assert get_base_dir(legacy=True) == os.path.expanduser("~root")
    monkeypatch.setenv("HOME", "/var/tmp/home")
    assert get_base_dir(legacy=True) == "/var/tmp/home"
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_base_dir(legacy=True) == "/var/tmp/base"
    # non-legacy is much easier:
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    assert get_base_dir(legacy=False) is None
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_base_dir(legacy=False) == "/var/tmp/base"


def test_get_base_dir_compat(monkeypatch):
    """test that it works the same for legacy and for non-legacy implementation"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    # old way: if BORG_BASE_DIR is not set, make something up with HOME/USER/~
    # new way: if BORG_BASE_DIR is not set, return None and let caller deal with it.
    assert get_base_dir(legacy=False) is None
    # new and old way: BORG_BASE_DIR overrides all other "base path determination".
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_base_dir(legacy=False) == get_base_dir(legacy=True)


def test_get_config_dir(monkeypatch):
    """test that get_config_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    home_dir = os.path.expanduser("~")
    if is_win32:
        monkeypatch.delenv("BORG_CONFIG_DIR", raising=False)
        assert get_config_dir(create=False) == os.path.join(home_dir, "AppData", "Local", "borg", "borg")
        monkeypatch.setenv("BORG_CONFIG_DIR", home_dir)
        assert get_config_dir(create=False) == home_dir
    elif is_darwin:
        monkeypatch.delenv("BORG_CONFIG_DIR", raising=False)
        assert get_config_dir(create=False) == os.path.join(home_dir, "Library", "Application Support", "borg")
        monkeypatch.setenv("BORG_CONFIG_DIR", "/var/tmp")
        assert get_config_dir(create=False) == "/var/tmp"
    else:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("BORG_CONFIG_DIR", raising=False)
        assert get_config_dir(create=False) == os.path.join(home_dir, ".config", "borg")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/var/tmp/.config")
        assert get_config_dir(create=False) == os.path.join("/var/tmp/.config", "borg")
        monkeypatch.setenv("BORG_CONFIG_DIR", "/var/tmp")
        assert get_config_dir(create=False) == "/var/tmp"


def test_get_config_dir_compat(monkeypatch):
    """test that it works the same for legacy and for non-legacy implementation"""
    monkeypatch.delenv("BORG_CONFIG_DIR", raising=False)
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    if not is_darwin and not is_win32:
        # fails on macOS: assert '/Users/tw/Library/Application Support/borg' == '/Users/tw/.config/borg'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_config_dir(legacy=False, create=False) == get_config_dir(legacy=True, create=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", "/var/tmp/xdg.config.d")
        # fails on macOS: assert '/Users/tw/Library/Application Support/borg' == '/var/tmp/xdg.config.d'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_config_dir(legacy=False, create=False) == get_config_dir(legacy=True, create=False)
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_config_dir(legacy=False, create=False) == get_config_dir(legacy=True, create=False)
    monkeypatch.setenv("BORG_CONFIG_DIR", "/var/tmp/borg.config.d")
    assert get_config_dir(legacy=False, create=False) == get_config_dir(legacy=True, create=False)


def test_get_cache_dir(monkeypatch):
    """test that get_cache_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    home_dir = os.path.expanduser("~")
    if is_win32:
        monkeypatch.delenv("BORG_CACHE_DIR", raising=False)
        assert get_cache_dir(create=False) == os.path.join(home_dir, "AppData", "Local", "borg", "borg", "Cache")
        monkeypatch.setenv("BORG_CACHE_DIR", home_dir)
        assert get_cache_dir(create=False) == home_dir
    elif is_darwin:
        monkeypatch.delenv("BORG_CACHE_DIR", raising=False)
        assert get_cache_dir(create=False) == os.path.join(home_dir, "Library", "Caches", "borg")
        monkeypatch.setenv("BORG_CACHE_DIR", "/var/tmp")
        assert get_cache_dir(create=False) == "/var/tmp"
    else:
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.delenv("BORG_CACHE_DIR", raising=False)
        assert get_cache_dir(create=False) == os.path.join(home_dir, ".cache", "borg")
        monkeypatch.setenv("XDG_CACHE_HOME", "/var/tmp/.cache")
        assert get_cache_dir(create=False) == os.path.join("/var/tmp/.cache", "borg")
        monkeypatch.setenv("BORG_CACHE_DIR", "/var/tmp")
        assert get_cache_dir(create=False) == "/var/tmp"


def test_get_cache_dir_compat(monkeypatch):
    """test that it works the same for legacy and for non-legacy implementation"""
    monkeypatch.delenv("BORG_CACHE_DIR", raising=False)
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    if not is_darwin and not is_win32:
        # fails on macOS: assert '/Users/tw/Library/Caches/borg' == '/Users/tw/.cache/borg'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_cache_dir(legacy=False, create=False) == get_cache_dir(legacy=True, create=False)
        # fails on macOS: assert '/Users/tw/Library/Caches/borg' == '/var/tmp/xdg.cache.d'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        monkeypatch.setenv("XDG_CACHE_HOME", "/var/tmp/xdg.cache.d")
        assert get_cache_dir(legacy=False, create=False) == get_cache_dir(legacy=True, create=False)
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_cache_dir(legacy=False, create=False) == get_cache_dir(legacy=True, create=False)
    monkeypatch.setenv("BORG_CACHE_DIR", "/var/tmp/borg.cache.d")
    assert get_cache_dir(legacy=False, create=False) == get_cache_dir(legacy=True, create=False)


def test_get_keys_dir(monkeypatch):
    """test that get_keys_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    home_dir = os.path.expanduser("~")
    if is_win32:
        monkeypatch.delenv("BORG_KEYS_DIR", raising=False)
        assert get_keys_dir(create=False) == os.path.join(home_dir, "AppData", "Local", "borg", "borg", "keys")
        monkeypatch.setenv("BORG_KEYS_DIR", home_dir)
        assert get_keys_dir(create=False) == home_dir
    elif is_darwin:
        monkeypatch.delenv("BORG_KEYS_DIR", raising=False)
        assert get_keys_dir(create=False) == os.path.join(home_dir, "Library", "Application Support", "borg", "keys")
        monkeypatch.setenv("BORG_KEYS_DIR", "/var/tmp")
        assert get_keys_dir(create=False) == "/var/tmp"
    else:
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("BORG_KEYS_DIR", raising=False)
        assert get_keys_dir(create=False) == os.path.join(home_dir, ".config", "borg", "keys")
        monkeypatch.setenv("XDG_CONFIG_HOME", "/var/tmp/.config")
        assert get_keys_dir(create=False) == os.path.join("/var/tmp/.config", "borg", "keys")
        monkeypatch.setenv("BORG_KEYS_DIR", "/var/tmp")
        assert get_keys_dir(create=False) == "/var/tmp"


def test_get_security_dir(monkeypatch):
    """test that get_security_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    home_dir = os.path.expanduser("~")
    if is_win32:
        monkeypatch.delenv("BORG_SECURITY_DIR", raising=False)
        assert get_security_dir(create=False) == os.path.join(home_dir, "AppData", "Local", "borg", "borg", "security")
        assert get_security_dir(repository_id="1234", create=False) == os.path.join(
            home_dir, "AppData", "Local", "borg", "borg", "security", "1234"
        )
        monkeypatch.setenv("BORG_SECURITY_DIR", home_dir)
        assert get_security_dir(create=False) == home_dir
    elif is_darwin:
        monkeypatch.delenv("BORG_SECURITY_DIR", raising=False)
        assert get_security_dir(create=False) == os.path.join(
            home_dir, "Library", "Application Support", "borg", "security"
        )
        assert get_security_dir(repository_id="1234", create=False) == os.path.join(
            home_dir, "Library", "Application Support", "borg", "security", "1234"
        )
        monkeypatch.setenv("BORG_SECURITY_DIR", "/var/tmp")
        assert get_security_dir(create=False) == "/var/tmp"
    else:
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.delenv("BORG_SECURITY_DIR", raising=False)
        assert get_security_dir(create=False) == os.path.join(home_dir, ".local", "share", "borg", "security")
        assert get_security_dir(repository_id="1234", create=False) == os.path.join(
            home_dir, ".local", "share", "borg", "security", "1234"
        )
        monkeypatch.setenv("XDG_DATA_HOME", "/var/tmp/.config")
        assert get_security_dir(create=False) == os.path.join("/var/tmp/.config", "borg", "security")
        monkeypatch.setenv("BORG_SECURITY_DIR", "/var/tmp")
        assert get_security_dir(create=False) == "/var/tmp"


def test_get_runtime_dir(monkeypatch):
    """test that get_runtime_dir respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    home_dir = os.path.expanduser("~")
    if is_win32:
        monkeypatch.delenv("BORG_RUNTIME_DIR", raising=False)
        assert get_runtime_dir(create=False) == os.path.join(home_dir, "AppData", "Local", "Temp", "borg", "borg")
        monkeypatch.setenv("BORG_RUNTIME_DIR", home_dir)
        assert get_runtime_dir(create=False) == home_dir
    elif is_darwin:
        monkeypatch.delenv("BORG_RUNTIME_DIR", raising=False)
        assert get_runtime_dir(create=False) == os.path.join(home_dir, "Library", "Caches", "TemporaryItems", "borg")
        monkeypatch.setenv("BORG_RUNTIME_DIR", "/var/tmp")
        assert get_runtime_dir(create=False) == "/var/tmp"
    else:
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        monkeypatch.delenv("BORG_RUNTIME_DIR", raising=False)
        uid = str(os.getuid())
        assert get_runtime_dir(create=False) in [
            os.path.join("/run/user", uid, "borg"),
            os.path.join("/var/run/user", uid, "borg"),
            os.path.join(f"/tmp/runtime-{uid}", "borg"),
        ]
        monkeypatch.setenv("XDG_RUNTIME_DIR", "/var/tmp/.cache")
        assert get_runtime_dir(create=False) == os.path.join("/var/tmp/.cache", "borg")
        monkeypatch.setenv("BORG_RUNTIME_DIR", "/var/tmp")
        assert get_runtime_dir(create=False) == "/var/tmp"


def test_dash_open():
    assert dash_open("-", "r") is sys.stdin
    assert dash_open("-", "w") is sys.stdout
    assert dash_open("-", "rb") is sys.stdin.buffer
    assert dash_open("-", "wb") is sys.stdout.buffer


@pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
def test_safe_unlink_is_safe(tmpdir):
    contents = b"Hello, world\n"
    victim = tmpdir / "victim"
    victim.write_binary(contents)
    hard_link = tmpdir / "hardlink"
    os.link(str(victim), str(hard_link))  # hard_link.mklinkto is not implemented on win32

    safe_unlink(hard_link)

    assert victim.read_binary() == contents


@pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
def test_safe_unlink_is_safe_ENOSPC(tmpdir, monkeypatch):
    contents = b"Hello, world\n"
    victim = tmpdir / "victim"
    victim.write_binary(contents)
    hard_link = tmpdir / "hardlink"
    os.link(str(victim), str(hard_link))  # hard_link.mklinkto is not implemented on win32

    def Path_unlink(_):
        raise OSError(errno.ENOSPC, "Pretend that we ran out of space")

    monkeypatch.setattr(Path, "unlink", Path_unlink)

    with pytest.raises(OSError):
        safe_unlink(hard_link)

    assert victim.read_binary() == contents


@pytest.mark.parametrize(
    "original_path, expected_path",
    [
        (".", "."),
        ("..", "."),
        ("/", "."),
        ("//", "."),
        ("foo", "foo"),
        ("foo/bar", "foo/bar"),
        ("/foo/bar", "foo/bar"),
        ("../foo/bar", "foo/bar"),
    ],
)
def test_remove_dotdot_prefixes(original_path, expected_path):
    assert remove_dotdot_prefixes(original_path) == expected_path


@pytest.mark.parametrize(
    "original_path, expected_path",
    [
        (".", "."),
        ("./", "."),
        ("/foo", "foo"),
        ("//foo", "foo"),
        (".//foo//bar//", "foo/bar"),
        ("/foo/bar", "foo/bar"),
        ("//foo/bar", "foo/bar"),
        ("//foo/./bar", "foo/bar"),
        (".test", ".test"),
        (".test.", ".test."),
        ("..test..", "..test.."),
        ("/te..st/foo/bar", "te..st/foo/bar"),
        ("/..test../abc//", "..test../abc"),
    ],
)
def test_valid_make_path_safe(original_path, expected_path):
    assert make_path_safe(original_path) == expected_path


@pytest.mark.parametrize("path", rejected_dotdot_paths)
def test_invalid_make_path_safe(path):
    with pytest.raises(ValueError, match="unexpected '..' element in path"):
        make_path_safe(path)


def test_dir_is_tagged(tmpdir):
    """Test dir_is_tagged with both path-based and file descriptor-based operations."""

    @contextmanager
    def open_dir(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            yield fd
        finally:
            os.close(fd)

    # Create directories for testing exclude_caches
    cache_dir = tmpdir.mkdir("cache_dir")
    cache_tag_path = cache_dir.join(CACHE_TAG_NAME)
    cache_tag_path.write_binary(CACHE_TAG_CONTENTS)

    invalid_cache_dir = tmpdir.mkdir("invalid_cache_dir")
    invalid_cache_tag_path = invalid_cache_dir.join(CACHE_TAG_NAME)
    invalid_cache_tag_path.write_binary(b"invalid signature")

    # Create directories for testing exclude_if_present
    tagged_dir = tmpdir.mkdir("tagged_dir")
    tag_file = tagged_dir.join(".NOBACKUP")
    tag_file.write("test")

    other_tagged_dir = tmpdir.mkdir("other_tagged_dir")
    other_tag_file = other_tagged_dir.join(".DONOTBACKUP")
    other_tag_file.write("test")

    # Create a directory with both a CACHEDIR.TAG and a custom tag file
    both_dir = tmpdir.mkdir("both_dir")
    cache_tag_path = both_dir.join(CACHE_TAG_NAME)
    cache_tag_path.write_binary(CACHE_TAG_CONTENTS)
    custom_tag_path = both_dir.join(".NOBACKUP")
    custom_tag_path.write("test")

    # Create a directory without any tag files
    normal_dir = tmpdir.mkdir("normal_dir")

    # Test edge cases
    test_dir = tmpdir.mkdir("test_dir")
    assert dir_is_tagged(path=str(test_dir), exclude_caches=None, exclude_if_present=None) == []
    assert dir_is_tagged(path=str(test_dir), exclude_if_present=[]) == []

    # Test with non-existent directory (should not raise an exception)
    non_existent_dir = str(tmpdir.join("non_existent"))
    result = dir_is_tagged(path=non_existent_dir, exclude_caches=True, exclude_if_present=[".NOBACKUP"])
    assert result == []

    # Test 1: exclude_caches with path-based operations
    assert dir_is_tagged(path=str(cache_dir), exclude_caches=True) == [CACHE_TAG_NAME]
    assert dir_is_tagged(path=str(invalid_cache_dir), exclude_caches=True) == []
    assert dir_is_tagged(path=str(normal_dir), exclude_caches=True) == []

    assert dir_is_tagged(path=str(cache_dir), exclude_caches=False) == []
    assert dir_is_tagged(path=str(invalid_cache_dir), exclude_caches=False) == []
    assert dir_is_tagged(path=str(normal_dir), exclude_caches=False) == []

    # Test 2: exclude_caches with file-descriptor-based operations
    with open_dir(str(cache_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True) == [CACHE_TAG_NAME]
    with open_dir(str(invalid_cache_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True) == []
    with open_dir(str(normal_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True) == []

    with open_dir(str(cache_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=False) == []
    with open_dir(str(invalid_cache_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=False) == []
    with open_dir(str(normal_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=False) == []

    # Test 3: exclude_if_present with path-based operations
    tags = [".NOBACKUP"]
    assert dir_is_tagged(path=str(tagged_dir), exclude_if_present=tags) == [".NOBACKUP"]
    assert dir_is_tagged(path=str(other_tagged_dir), exclude_if_present=tags) == []
    assert dir_is_tagged(path=str(normal_dir), exclude_if_present=tags) == []

    tags = [".NOBACKUP", ".DONOTBACKUP"]
    assert dir_is_tagged(path=str(tagged_dir), exclude_if_present=tags) == [".NOBACKUP"]
    assert dir_is_tagged(path=str(other_tagged_dir), exclude_if_present=tags) == [".DONOTBACKUP"]
    assert dir_is_tagged(path=str(normal_dir), exclude_if_present=tags) == []

    # Test 4: exclude_if_present with file descriptor-based operations
    tags = [".NOBACKUP"]
    with open_dir(str(tagged_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == [".NOBACKUP"]
    with open_dir(str(other_tagged_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == []
    with open_dir(str(normal_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == []

    tags = [".NOBACKUP", ".DONOTBACKUP"]
    with open_dir(str(tagged_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == [".NOBACKUP"]
    with open_dir(str(other_tagged_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == [".DONOTBACKUP"]
    with open_dir(str(normal_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_if_present=tags) == []

    # Test 5: both exclude types with path-based operations
    assert sorted(dir_is_tagged(path=str(both_dir), exclude_caches=True, exclude_if_present=[".NOBACKUP"])) == [
        ".NOBACKUP",
        CACHE_TAG_NAME,
    ]
    assert dir_is_tagged(path=str(cache_dir), exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == [CACHE_TAG_NAME]
    assert dir_is_tagged(path=str(tagged_dir), exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == [".NOBACKUP"]
    assert dir_is_tagged(path=str(normal_dir), exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == []

    # Test 6: both exclude types with file descriptor-based operations
    with open_dir(str(both_dir)) as fd:
        assert sorted(dir_is_tagged(dir_fd=fd, exclude_caches=True, exclude_if_present=[".NOBACKUP"])) == [
            ".NOBACKUP",
            CACHE_TAG_NAME,
        ]
    with open_dir(str(cache_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == [CACHE_TAG_NAME]
    with open_dir(str(tagged_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == [".NOBACKUP"]
    with open_dir(str(normal_dir)) as fd:
        assert dir_is_tagged(dir_fd=fd, exclude_caches=True, exclude_if_present=[".NOBACKUP"]) == []
