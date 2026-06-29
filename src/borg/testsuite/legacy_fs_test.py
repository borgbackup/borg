"""Tests for borg.legacy.fs (borg 1.x directory layout).

These mirror the directory-resolution tests that used to live in
testsuite/helpers/fs_test.py with a ``legacy=True`` flag, before the borg 1.x
layout was split out into borg.legacy.fs (issue #9556).
"""

import os

from ..helpers.fs import get_base_dir, get_config_dir, get_cache_dir
from ..legacy.fs import (
    get_base_dir as get_base_dir_legacy,
    get_config_dir as get_config_dir_legacy,
    get_cache_dir as get_cache_dir_legacy,
)
from ..platform import is_win32, is_darwin, is_haiku, is_cygwin


def test_get_base_dir(monkeypatch):
    """test that the borg 1.x base dir resolution respects environment"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("USER", raising=False)
    assert get_base_dir_legacy() == os.path.expanduser("~")
    # Haiku OS is a single-user OS, expanding "~root" is not supported.
    if not (is_haiku or is_cygwin):
        monkeypatch.setenv("USER", "root")
        assert get_base_dir_legacy() == os.path.expanduser("~root")
    monkeypatch.setenv("HOME", "/var/tmp/home")
    assert get_base_dir_legacy() == "/var/tmp/home"
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_base_dir_legacy() == "/var/tmp/base"


def test_get_base_dir_compat(monkeypatch):
    """test that modern and borg 1.x base dir resolution agree where they should"""
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    # modern way: if BORG_BASE_DIR is not set, return None and let caller deal with it.
    assert get_base_dir() is None
    # both ways: BORG_BASE_DIR overrides all other "base path determination".
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_base_dir() == get_base_dir_legacy()


def test_get_config_dir_compat(monkeypatch):
    """test that modern and borg 1.x config dir resolution agree where they should"""
    monkeypatch.delenv("BORG_CONFIG_DIR", raising=False)
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    if not is_darwin and not is_win32:
        # fails on macOS: assert '/Users/tw/Library/Application Support/borg' == '/Users/tw/.config/borg'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_config_dir(create=False) == get_config_dir_legacy(create=False)
    if not is_win32:
        monkeypatch.setenv("XDG_CONFIG_HOME", "/var/tmp/xdg.config.d")
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_config_dir(create=False) == get_config_dir_legacy(create=False)
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_config_dir(create=False) == get_config_dir_legacy(create=False)
    monkeypatch.setenv("BORG_CONFIG_DIR", "/var/tmp/borg.config.d")
    assert get_config_dir(create=False) == get_config_dir_legacy(create=False)


def test_get_cache_dir_compat(monkeypatch):
    """test that modern and borg 1.x cache dir resolution agree where they should"""
    monkeypatch.delenv("BORG_CACHE_DIR", raising=False)
    monkeypatch.delenv("BORG_BASE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    if not is_darwin and not is_win32:
        # fails on macOS: assert '/Users/tw/Library/Caches/borg' == '/Users/tw/.cache/borg'
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        assert get_cache_dir(create=False) == get_cache_dir_legacy(create=False)
    if not is_win32:
        # fails on win32 MSYS2 (but we do not need legacy compat there).
        monkeypatch.setenv("XDG_CACHE_HOME", "/var/tmp/xdg.cache.d")
        assert get_cache_dir(create=False) == get_cache_dir_legacy(create=False)
    monkeypatch.setenv("BORG_BASE_DIR", "/var/tmp/base")
    assert get_cache_dir(create=False) == get_cache_dir_legacy(create=False)
    monkeypatch.setenv("BORG_CACHE_DIR", "/var/tmp/borg.cache.d")
    assert get_cache_dir(create=False) == get_cache_dir_legacy(create=False)
