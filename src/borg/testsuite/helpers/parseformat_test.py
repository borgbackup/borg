import base64
import os
from datetime import datetime, timezone

import pytest

from ...constants import * # NOQA
from ...helpers.argparsing import ArgumentTypeError
from ...helpers.parseformat import (
    bin_to_hex,
    binary_to_json,
    text_to_json,
    Location,
    archivename_validator,
    text_validator,
    format_file_size,
    parse_file_size,
    interval,
    partial_format,
    clean_lines,
    format_line,
    PlaceholderError,
    replace_placeholders,
    swidth_slice,
    eval_escapes,
    ChunkerParams,
    FilesCacheMode,
)
from ...helpers.time import format_timedelta, parse_timestamp
from ...platformflags import is_win32


def test_bin_to_hex():
    assert bin_to_hex(b"") == ""
    assert bin_to_hex(b"\x00\x01\xff") == "0001ff"


@pytest.mark.parametrize(
    "key,value",
    [("key", b"\x00\x01\x02\x03"), ("key", b"\x00\x01\x02"), ("key", b"\x00\x01"), ("key", b"\x00"), ("key", b"")],
)
def test_binary_to_json(key, value):
    key_b64 = key + "_b64"
    d = binary_to_json(key, value)
    assert key_b64 in d
    assert base64.b64decode(d[key_b64]) == value


@pytest.mark.parametrize(
    "key,value,strict",
    [
        ("key", "abc", True),
        ("key", "äöü", True),
        ("key", "", True),
        ("key", b"\x00\xff".decode("utf-8", errors="surrogateescape"), False),
        ("key", "äöü".encode("latin1").decode("utf-8", errors="surrogateescape"), False),
    ],
)
def test_text_to_json(key, value, strict):
    key_b64 = key + "_b64"
    d = text_to_json(key, value)
    value_b = value.encode("utf-8", errors="surrogateescape")
    if strict:
        assert key in d
        assert d[key] == value_b.decode("utf-8", errors="strict")
        assert d[key].encode("utf-8", errors="strict") == value_b
        assert key_b64 not in d
    else:
        assert key in d
        assert d[key] == value.encode("utf-8", errors="replace").decode("utf-8", errors="strict")
        assert d[key].encode("utf-8", errors="strict") == value.encode("utf-8", errors="replace")
        assert key_b64 in d
        assert base64.b64decode(d[key_b64]) == value_b


class TestLocationWithoutEnv:
    @pytest.fixture
    def keys_dir(self, tmpdir, monkeypatch):
        tmpdir = str(tmpdir)
        monkeypatch.setenv("BORG_KEYS_DIR", tmpdir)
        if not tmpdir.endswith(os.path.sep):
            tmpdir += os.path.sep
        return tmpdir

    def test_ssh(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("ssh://user@host:1234//absolute/path"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=1234, path='/absolute/path')"
        )
        assert Location("ssh://user@host:1234//absolute/path").to_key_filename() == keys_dir + "host___absolute_path"

    def test_bad_syntax(self):
        with pytest.raises(ValueError):
            Location("ssh://user@host:/path")


def test_archivename_ok(name="foobar"):
    assert archivename_validator(name) == name


def test_files_cache_mode_win32_restriction(monkeypatch):
    from borg.helpers import parseformat

    monkeypatch.setattr(parseformat, "is_win32", True)
    with pytest.raises(ArgumentTypeError, match="ctime is not supported"):
        FilesCacheMode("cis")
    with pytest.raises(ArgumentTypeError, match="ctime is not supported"):
        FilesCacheMode("ctime,size")
    assert FilesCacheMode("ims") == "ims"
    monkeypatch.setattr(parseformat, "is_win32", False)
    assert FilesCacheMode("cis") == "cis"