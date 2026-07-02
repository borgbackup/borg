import base64
import json
import ntpath
import os

import re
import unicodedata
from datetime import datetime, timedelta, timezone

import pytest

from ...constants import *  # NOQA
from ...helpers import parseformat
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
    int_or_interval,
    nonnegative_seconds,
    partial_format,
    clean_lines,
    format_line,
    PlaceholderError,
    replace_placeholders,
    swidth_slice,
    eval_escapes,
    ChunkerParams,
    DigestAlgos,
    files_cache_mode_no_ctime,
    get_size_units,
    normalize_local_path,
    ArchiveFormatter,
    DiffFormatter,
    ItemFormatter,
)
from ...helpers.errors import CommandError
from ...helpers.time import format_timedelta, parse_timestamp
from ...item import Item, ItemDiff
from ...platformflags import is_win32, is_darwin


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
        # No surrogate escapes; just Unicode text.
        assert key in d
        assert d[key] == value_b.decode("utf-8", errors="strict")
        assert d[key].encode("utf-8", errors="strict") == value_b
        assert key_b64 not in d  # Not needed; pure valid Unicode.
    else:
        # Requires surrogate escapes. The text has replacement characters; Base64 representation is present.
        assert key in d
        assert d[key] == value.encode("utf-8", errors="replace").decode("utf-8", errors="strict")
        assert d[key].encode("utf-8", errors="strict") == value.encode("utf-8", errors="replace")
        assert key_b64 in d
        assert base64.b64decode(d[key_b64]) == value_b


class TestLocationWithoutEnv:
    def test_ssh(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("ssh://user@host:1234//absolute/path"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=1234, path='/absolute/path')"
        )
        assert (
            repr(Location("ssh://user@host:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@host/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[::]:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='::', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[::]/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::c0:ffee', port=1234, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::c0:ffee', port=None, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::192.0.2.1', port=1234, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='2001:db8::192.0.2.1', port=None, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]:1234/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=1234, path='relative/path')"
        )

    def test_rest(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("rest://user@host:1234//absolute/path"))
            == "Location(proto='rest', user='user', pass=None, host='host', port=1234, path='/absolute/path')"
        )
        assert (
            repr(Location("rest://user@host:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='host', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@host/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='host', port=None, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[::]:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='::', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[::]/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[2001:db8::]:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[2001:db8::]/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[2001:db8::c0:ffee]:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::c0:ffee', port=1234, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("rest://user@[2001:db8::c0:ffee]/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::c0:ffee', port=None, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("rest://user@[2001:db8::192.0.2.1]:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::192.0.2.1', port=1234, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("rest://user@[2001:db8::192.0.2.1]/relative/path"))
            == "Location(proto='rest', user='user', pass=None, host='2001:db8::192.0.2.1', port=None, path='relative/path')"  # noqa: E501
        )
        assert (
            repr(Location("rest://user@[2a02:0001:0002:0003:0004:0005:0006:0007]/relative/path"))
            == "Location(proto='rest', user='user', pass=None, "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=None, path='relative/path')"
        )
        assert (
            repr(Location("rest://user@[2a02:0001:0002:0003:0004:0005:0006:0007]:1234/relative/path"))
            == "Location(proto='rest', user='user', pass=None, "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("rest:///relative/path"))
            == "Location(proto='rest', user=None, pass=None, host=None, port=None, path='relative/path')"
        )
        assert (
            repr(Location("rest:////absolute/path"))
            == "Location(proto='rest', user=None, pass=None, host=None, port=None, path='/absolute/path')"
        )

    def test_server_side_path_is_posix(self, monkeypatch):
        # ssh:// and rest:// paths live on the *server*, so they must be normalized as POSIX
        # paths, no matter what the client runs on. A Windows client used to normalize them
        # with ntpath, turning "/path/to/repo" into "\path\to\repo"; ssh passes the command
        # through the remote shell, which ate the backslashes and left "pathtorepo", see #10199.
        #
        # The windows_tests CI job can not catch this: it runs in an msys2 shell, and MSYS2's
        # mingw python switches ntpath.sep to "/" when MSYSTEM is set, so ntpath behaves like
        # posixpath there. Users running borg.exe from cmd/PowerShell get the real ntpath.
        # Faking a Windows client by swapping in ntpath tests this on any platform instead.
        monkeypatch.delenv("BORG_REPO", raising=False)
        monkeypatch.setattr(parseformat.os, "path", ntpath)
        for proto in ("ssh", "rest"):
            assert Location(f"{proto}://user@host/relative/path").path == "relative/path"
            assert Location(f"{proto}://user@host//absolute/path").path == "/absolute/path"
            assert Location(f"{proto}://user@host:1234//absolute/path").path == "/absolute/path"
            assert Location(f"{proto}://user@host//absolute/./x/../path").path == "/absolute/path"
            assert (
                Location(f"{proto}://user@host//absolute/path").canonical_path()
                == f"{proto}://user@host//absolute/path"
            )

    # For the protocols handled (parsed + validated) by borgstore itself, borg only detects
    # the scheme and passes the raw URL through; it no longer extracts user/host/port/path.

    def test_s3(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        loc = Location("s3:/test/path")
        assert loc.proto == "s3"
        assert (loc.user, loc.host, loc.port, loc.path) == (None, None, None, None)
        assert loc.processed == "s3:/test/path"
        # credentials in the URL are stripped from canonical_path (security state file / logs)
        assert Location("s3:profile@http://172.28.52.116:9000/test/path").canonical_path() == (
            "s3:http://172.28.52.116:9000/test/path"
        )
        assert Location("s3:user:pass@http://172.28.52.116:9000/test/path").canonical_path() == (
            "s3:http://172.28.52.116:9000/test/path"
        )
        assert Location("b2:user:pass@https://s3.us-east-005.backblazeb2.com/test/path").canonical_path() == (
            "b2:https://s3.us-east-005.backblazeb2.com/test/path"
        )

    def test_rclone(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        loc = Location("rclone:remote:path")
        assert loc.proto == "rclone"
        assert (loc.user, loc.host, loc.port, loc.path) == (None, None, None, None)
        assert loc.processed == "rclone:remote:path"
        assert loc.canonical_path() == "rclone:remote:path"

    def test_sftp(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        loc = Location("sftp://user@host:1234/rel/path")
        assert loc.proto == "sftp"
        assert (loc.user, loc.host, loc.port, loc.path) == (None, None, None, None)
        assert loc.processed == "sftp://user@host:1234/rel/path"
        # credentials stripped from canonical_path
        assert loc.canonical_path() == "sftp://host:1234/rel/path"

    def test_http(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        loc = Location("http://user:pass@host:1234/")
        assert loc.proto == "http"
        assert (loc.user, loc.host, loc.port, loc.path) == (None, None, None, None)
        assert loc.processed == "http://user:pass@host:1234/"
        # credentials stripped from canonical_path
        assert loc.canonical_path() == "http://host:1234/"

    def test_file(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        url = "file:///c:/repo/path" if is_win32 else "file:///repo/path"
        path = "c:/repo/path" if is_win32 else "/repo/path"
        assert (
            repr(Location(url)) == f"Location(proto='file', user=None, pass=None, host=None, port=None, path='{path}')"
        )

    def test_unc_rejected(self, monkeypatch):
        # UNC paths are not supported (#3141), the parser rejects all spellings early, see #10164.
        monkeypatch.delenv("BORG_REPO", raising=False)
        with pytest.raises(ValueError, match="UNC paths are not supported"):
            Location("//server/share/repo")
        # on win32, file:/// must be followed by a drive letter, so this is invalid even earlier.
        with pytest.raises(ValueError, match="Invalid location" if is_win32 else "UNC paths are not supported"):
            Location("file:////server/share/repo")
        if is_win32:
            with pytest.raises(ValueError, match="UNC paths are not supported"):
                Location(r"\\server\share\repo")

    def test_folder(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        rel_path = "path"
        abs_path = os.path.abspath(rel_path)
        assert (
            repr(Location(rel_path))
            == f"Location(proto='file', user=None, pass=None, host=None, port=None, path='{abs_path}')"
        )

    @pytest.mark.skipif(is_win32, reason="Windows has drive letters in abs paths")
    def test_abspath(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/some/absolute/path"))
            == "Location(proto='file', user=None, pass=None, host=None, port=None, path='/some/absolute/path')"
        )
        assert (
            repr(Location("/some/../absolute/path"))
            == "Location(proto='file', user=None, pass=None, host=None, port=None, path='/absolute/path')"
        )

    def test_relpath(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        # For a local path, Borg creates a Location instance with an absolute path.
        rel_path = "relative/path"
        abs_path = os.path.abspath(rel_path)
        assert (
            repr(Location(rel_path))
            == f"Location(proto='file', user=None, pass=None, host=None, port=None, path='{abs_path}')"
        )
        assert (
            repr(Location("ssh://user@host/relative/path"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=None, path='relative/path')"
        )

    @pytest.mark.skipif(is_win32, reason="Windows does not support colons in paths")
    def test_with_colons(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/abs/path:w:cols"))
            == "Location(proto='file', user=None, pass=None, host=None, port=None, path='/abs/path:w:cols')"
        )
        assert (
            repr(Location("file:///abs/path:w:cols"))
            == "Location(proto='file', user=None, pass=None, host=None, port=None, path='/abs/path:w:cols')"
        )
        assert (
            repr(Location("ssh://user@host/abs/path:w:cols"))
            == "Location(proto='ssh', user='user', pass=None, host='host', port=None, path='abs/path:w:cols')"
        )

    def test_canonical_path(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        locations = [
            "relative/path",
            "ssh://host/relative/path",
            "ssh://host//absolute/path",
            "ssh://user@host:1234/relative/path",
            "sftp://host/relative/path",
            "sftp://host//absolute/path",
            "sftp://user@host:1234/relative/path",
            "rclone:remote:path",
        ]
        locations.insert(1, "c:/absolute/path" if is_win32 else "/absolute/path")
        locations.insert(2, "file:///c:/absolute/path" if is_win32 else "file:///absolute/path")
        for location in locations:
            assert (
                Location(location).canonical_path() == Location(Location(location).canonical_path()).canonical_path()
            ), ("failed: %s" % location)

    def test_bad_syntax(self):
        with pytest.raises(ValueError):
            # This is invalid due to the second colon. Correct: 'ssh://user@host/path'.
            Location("ssh://user@host:/path")


def test_normalize_local_path():
    nfc = unicodedata.normalize("NFC", "tëst")  # composed: ë is a single codepoint
    nfd = unicodedata.normalize("NFD", "tëst")  # decomposed: e + combining diaeresis
    assert nfc != nfd  # sanity: the two unicode forms really differ byte-wise
    if is_darwin:
        # on macOS both forms normalize to the same (NFD) form the filesystem uses
        assert normalize_local_path(nfc) == normalize_local_path(nfd) == nfd
    else:
        # elsewhere it is a no-op
        assert normalize_local_path(nfc) == nfc
        assert normalize_local_path(nfd) == nfd


def test_canonical_path_unicode_normalization(monkeypatch):
    # regression test for #2913: a file repo path entered in NFC form (e.g. typed as an argument) and
    # the same path in NFD form (e.g. derived from os.getcwd() on macOS) must yield the same canonical
    # path, so borg does not mistake identical-looking paths for a repository relocation.
    monkeypatch.delenv("BORG_REPO", raising=False)
    nfc = unicodedata.normalize("NFC", "/absolute/tëst")
    nfd = unicodedata.normalize("NFD", "/absolute/tëst")
    if is_darwin:
        assert Location(nfc).canonical_path() == Location(nfd).canonical_path()
    else:
        # on other platforms the filesystem does not normalize, so the forms stay distinct
        assert Location(nfc).canonical_path() != Location(nfd).canonical_path()


@pytest.mark.parametrize(
    "name",
    [
        "foobar",
        # Placeholders
        "foobar-{now}",
    ],
)
def test_archivename_ok(name):
    assert archivename_validator(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",  # too short
        "x" * 201,  # too long
        # Invalid characters:
        "foo/bar",
        "foo\\bar",
        ">foo",
        "<foo",
        "|foo",
        'foo"bar',
        "foo?",
        "*bar",
        "foo\nbar",
        "foo\0bar",
        # Leading/trailing blanks
        " foo",
        "bar  ",
        # Contains surrogate escapes
        "foo\udc80bar",
        "foo\udcffbar",
    ],
)
def test_archivename_invalid(name):
    with pytest.raises(ArgumentTypeError):
        archivename_validator(name)


@pytest.mark.parametrize("text", ["", "single line", "multi\nline\ncomment"])
def test_text_ok(text):
    assert text_validator(name="text", max_length=100)(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "x" * 101,  # too long
        # Invalid characters:
        "foo\0bar",
        # Contains surrogate escapes
        "foo\udc80bar",
        "foo\udcffbar",
    ],
)
def test_text_invalid(text):
    invalid_ctrl_chars = "".join(chr(i) for i in range(32))
    tv = text_validator(name="text", max_length=100, min_length=1, invalid_ctrl_chars=invalid_ctrl_chars)
    with pytest.raises(ArgumentTypeError):
        tv(text)


def test_format_timedelta():
    t0 = datetime(2001, 1, 1, 10, 20, 3, 0)
    t1 = datetime(2001, 1, 1, 12, 20, 4, 100000)
    assert format_timedelta(t1 - t0) == "2 hours 1.100 seconds"


@pytest.mark.parametrize(
    "timeframe, num_secs",
    [
        ("0S", timedelta(seconds=0)),
        ("5S", timedelta(seconds=5)),
        ("2M", timedelta(minutes=2)),
        ("1H", timedelta(hours=1)),
        ("1d", timedelta(days=1)),
        ("1w", timedelta(days=7)),
        ("1m", timedelta(days=31)),
        ("1y", timedelta(days=365)),
    ],
)
def test_interval(timeframe, num_secs):
    assert interval(timeframe) == num_secs


@pytest.mark.parametrize(
    "invalid_interval, error_tuple",
    [
        ("H", ('Invalid number "": expected nonnegative integer',)),
        ("-1d", ('Invalid number "-1": expected nonnegative integer',)),
        ("food", ('Invalid number "foo": expected nonnegative integer',)),
    ],
)
def test_interval_time_unit(invalid_interval, error_tuple):
    with pytest.raises(ArgumentTypeError) as exc:
        interval(invalid_interval)
    assert exc.value.args == error_tuple


@pytest.mark.parametrize(
    "invalid_input, error_regex",
    [
        ("x", r'^Unexpected time unit "x": choose from'),
        ("-1t", r'^Unexpected time unit "t": choose from'),
        ("fool", r'^Unexpected time unit "l": choose from'),
        ("abc", r'^Unexpected time unit "c": choose from'),
        (" abc ", r'^Unexpected time unit " ": choose from'),
    ],
)
def test_interval_invalid_time_format(invalid_input, error_regex):
    with pytest.raises(ArgumentTypeError) as exc:
        interval(invalid_input)
    assert re.search(error_regex, exc.value.args[0])


@pytest.mark.parametrize("input, result", [("0", 0.0), ("30", 30.0), ("2.5", 2.5), ("1800", 1800.0)])
def test_nonnegative_seconds(input, result):
    assert nonnegative_seconds(input) == result


@pytest.mark.parametrize("invalid_input", ["-1", "-0.5", "foo", ""])
def test_nonnegative_seconds_invalid(invalid_input):
    with pytest.raises(ArgumentTypeError):
        nonnegative_seconds(invalid_input)


@pytest.mark.parametrize(
    "input, result",
    [
        ("0", 0),
        ("5", 5),
        (" 999 ", 999),
        ("-1", -1),
        ("all", -1),
        ("0S", timedelta(seconds=0)),
        ("5S", timedelta(seconds=5)),
        ("1m", timedelta(days=31)),
        # already-converted values (jsonargparse idempotency)
        (0, 0),
        (5, 5),
        (timedelta(seconds=5), timedelta(seconds=5)),
        (timedelta(days=31), timedelta(days=31)),
    ],
)
def test_int_or_interval(input, result):
    assert int_or_interval(input) == result


@pytest.mark.parametrize(
    "invalid_input, error_regex",
    [
        ("H", r"Value is neither an integer nor an interval:"),
        ("-1d", r"Value is neither an integer nor an interval:"),
        ("food", r"Value is neither an integer nor an interval:"),
    ],
)
def test_int_or_interval_time_unit(invalid_input, error_regex):
    with pytest.raises(ArgumentTypeError) as exc:
        int_or_interval(invalid_input)
    assert re.search(error_regex, exc.value.args[0])


def test_parse_timestamp():
    assert parse_timestamp("2015-04-19T20:25:00.226410") == datetime(2015, 4, 19, 20, 25, 0, 226410, timezone.utc)
    assert parse_timestamp("2015-04-19T20:25:00") == datetime(2015, 4, 19, 20, 25, 0, 0, timezone.utc)


@pytest.mark.parametrize(
    "size, fmt",
    [
        (0, "0 B"),  # No rounding necessary for these.
        (1, "1 B"),
        (142, "142 B"),
        (999, "999 B"),
        (1000, "1.00 kB"),  # rounding starts here
        (1001, "1.00 kB"),  # should be rounded away
        (1234, "1.23 kB"),  # should be rounded down
        (1235, "1.24 kB"),  # should be rounded up
        (1010, "1.01 kB"),  # rounded down as well
        (999990000, "999.99 MB"),  # rounded down
        (999990001, "999.99 MB"),  # rounded down
        (999995000, "1.00 GB"),  # Rounded up to the next unit.
        (10**6, "1.00 MB"),  # and all the remaining units, megabytes
        (10**9, "1.00 GB"),  # gigabytes
        (10**12, "1.00 TB"),  # terabytes
        (10**15, "1.00 PB"),  # petabytes
        (10**18, "1.00 EB"),  # exabytes
        (10**21, "1.00 ZB"),  # zettabytes
        (10**24, "1.00 YB"),  # yottabytes
        (-1, "-1 B"),  # negative value
        (-1010, "-1.01 kB"),  # negative value with rounding
    ],
)
def test_file_size(size, fmt):
    """test the size formatting routines"""
    assert format_file_size(size) == fmt


@pytest.mark.parametrize(
    "size, fmt",
    [
        (0, "0 B"),
        (2**0, "1 B"),
        (2**10, "1.00 KiB"),
        (2**20, "1.00 MiB"),
        (2**30, "1.00 GiB"),
        (2**40, "1.00 TiB"),
        (2**50, "1.00 PiB"),
        (2**60, "1.00 EiB"),
        (2**70, "1.00 ZiB"),
        (2**80, "1.00 YiB"),
        (-(2**0), "-1 B"),
        (-(2**10), "-1.00 KiB"),
        (-(2**20), "-1.00 MiB"),
    ],
)
def test_file_size_iec(monkeypatch, size, fmt):
    """test the size formatting routines"""
    monkeypatch.setenv("BORG_UNITS", "iec")
    assert format_file_size(size) == fmt


@pytest.mark.parametrize(
    "units, expected",
    [
        (None, "si"),  # BORG_UNITS not set
        ("", "si"),
        ("si", "si"),
        ("iec", "iec"),
        ("raw", "raw"),
        ("IEC", "iec"),  # value is case insensitive
        (" raw ", "raw"),  # and gets stripped
        ("bytes", "si"),  # invalid value: warn and ignore
        ("yes", "si"),  # the removed BORG_IEC's value is not accepted either
    ],
)
def test_get_size_units(monkeypatch, units, expected):
    """size units are requested via the BORG_UNITS environment variable"""
    monkeypatch.delenv("BORG_UNITS", raising=False)
    if units is not None:
        monkeypatch.setenv("BORG_UNITS", units)
    assert get_size_units() == expected


def test_borg_iec_is_gone(monkeypatch):
    """the removed BORG_IEC environment variable has no effect any more"""
    monkeypatch.delenv("BORG_UNITS", raising=False)
    monkeypatch.setenv("BORG_IEC", "yes")
    assert get_size_units() == "si"
    assert format_file_size(2**20) == "1.05 MB"


def test_get_size_units_invalid_warns(monkeypatch, caplog):
    """an invalid BORG_UNITS value is complained about, but only once"""
    from ...helpers import parseformat

    monkeypatch.delenv("BORG_UNITS", raising=False)
    monkeypatch.setattr(parseformat, "_warned_units", set())
    monkeypatch.setenv("BORG_UNITS", "kibibytes")
    with caplog.at_level("WARNING"):
        assert get_size_units() == "si"
        assert get_size_units() == "si"
    assert len([record for record in caplog.records if "kibibytes" in record.message]) == 1


@pytest.mark.parametrize(
    "size, kwargs, fmt",
    [
        (0, {}, "0 B"),
        (1, {}, "1 B"),
        (1234, {}, "1234 B"),  # not scaled down to 1.23 kB
        (10**15, {}, "1000000000000000 B"),
        (-1234, {}, "-1234 B"),
        (1234, dict(precision=0), "1234 B"),  # precision does not matter
        (1234, dict(sign=True), "+1234 B"),
        (-1234, dict(sign=True), "-1234 B"),
        (0, dict(sign=True), "0 B"),
        (1234.56, {}, "1235 B"),  # a float (e.g. a throughput value) is rounded
    ],
)
def test_file_size_raw(monkeypatch, size, kwargs, fmt):
    """BORG_UNITS=raw gives exact byte counts, so scripts can easily parse them"""
    monkeypatch.setenv("BORG_UNITS", "raw")
    assert format_file_size(size, **kwargs) == fmt


@pytest.mark.parametrize(
    "units, fmt", [(None, "1.05 MB"), ("si", "1.05 MB"), ("iec", "1.00 MiB"), ("raw", "1048576 B")]  # si is the default
)
def test_file_size_units_from_env(monkeypatch, units, fmt):
    """format_file_size uses the units requested via BORG_UNITS"""
    monkeypatch.delenv("BORG_UNITS", raising=False)
    if units is not None:
        monkeypatch.setenv("BORG_UNITS", units)
    assert format_file_size(2**20) == fmt


@pytest.mark.parametrize(
    "original_size, formatted_size",
    [
        (1234, "1.2 kB"),  # rounded down
        (1254, "1.3 kB"),  # rounded up
        (999990000, "1.0 GB"),  # and not 999.9 MB or 1000.0 MB
    ],
)
def test_file_size_precision(original_size, formatted_size):
    assert format_file_size(original_size, precision=1) == formatted_size


@pytest.mark.parametrize("size, fmt", [(0, "0 B"), (1, "+1 B"), (1234, "+1.23 kB"), (-1, "-1 B"), (-1234, "-1.23 kB")])
def test_file_size_sign(size, fmt):
    assert format_file_size(size, sign=True) == fmt


@pytest.mark.parametrize(
    "size, fmt",
    [
        (0, "0 B"),  # bytes and kB are formatted like with fine=False
        (999, "999 B"),
        (1234, "1.23 kB"),
        (10**6, "1.00 MB"),  # MB: 2 decimals, like with fine=False
        (1234567, "1.23 MB"),
        (10**9, "1.000 GB"),  # GB: 3 decimals
        (1234567890, "1.235 GB"),
        (999995000, "1.000 GB"),  # rounded up to the next unit, like with fine=False
        (999994999999, "999.995 GB"),  # almost 1 TB, but still shown as GB
        (999999000000, "0.999999 TB"),  # unit like with fine=False ("1.00 TB"), but exact value
        (10**12, "1.000000 TB"),  # TB: 6 decimals
        (5000001000000, "5.000001 TB"),  # 1 MB more is visible now, that is the point of #3559
        (10**15, "1.000000000 PB"),  # PB: 9 decimals
        (5 * 10**15 + 10**6, "5.000000001 PB"),
        (10**18, "1.000000000 EB"),  # decimals are capped at 9
        (-(10**12), "-1.000000 TB"),
    ],
)
def test_file_size_fine(size, fmt):
    """fine=True shows big sizes with more decimals, so that changes of ~1MB stay visible"""
    assert format_file_size(size, fine=True) == fmt


@pytest.mark.parametrize(
    "size, fmt",
    [
        (2**20, "1.00 MiB"),
        (2**30, "1.000 GiB"),
        (2**40, "1.000000 TiB"),
        (2**40 + 2**20, "1.000001 TiB"),
        (2**50 + 2**20, "1.000000001 PiB"),
    ],
)
def test_file_size_fine_iec(monkeypatch, size, fmt):
    monkeypatch.setenv("BORG_UNITS", "iec")
    assert format_file_size(size, fine=True) == fmt


def test_file_size_fine_raw(monkeypatch):
    """BORG_UNITS=raw is exact anyway, so fine does not change anything"""
    monkeypatch.setenv("BORG_UNITS", "raw")
    assert format_file_size(10**12, fine=True) == "1000000000000 B"


def test_file_size_fine_sign():
    assert format_file_size(10**12, sign=True, fine=True) == "+1.000000 TB"


@pytest.mark.parametrize(
    "string, value", [("1", 1), ("20", 20), ("5K", 5000), ("1.75M", 1750000), ("1e+9", 1e9), ("-1T", -1e12)]
)
def test_parse_file_size(string, value):
    assert parse_file_size(string) == int(value)


@pytest.mark.parametrize("string", ("", "5 Äpfel", "4E", "2229 bit", "1B"))
def test_parse_file_size_invalid(string):
    with pytest.raises(ValueError):
        parse_file_size(string)


@pytest.mark.parametrize(
    "fmt, items_map, expected_result",
    [
        ("{space:10}", {"space": " "}, " " * 10),
        ("{foobar}", {"bar": "wrong", "foobar": "correct"}, "correct"),
        ("{unknown_key}", {}, "{unknown_key}"),
        ("{key}{{escaped_key}}", {}, "{key}{{escaped_key}}"),
        ("{{escaped_key}}", {"escaped_key": 1234}, "{{escaped_key}}"),
    ],
)
def test_partial_format(fmt, items_map, expected_result):
    assert partial_format(fmt, items_map) == expected_result


def test_clean_lines():
    conf = """\
#comment
data1 #data1
data2

 data3
""".splitlines(
        keepends=True
    )
    assert list(clean_lines(conf)) == ["data1 #data1", "data2", "data3"]
    assert list(clean_lines(conf, lstrip=False)) == ["data1 #data1", "data2", " data3"]
    assert list(clean_lines(conf, rstrip=False)) == ["data1 #data1\n", "data2\n", "data3\n"]
    assert list(clean_lines(conf, remove_empty=False)) == ["data1 #data1", "data2", "", "data3"]
    assert list(clean_lines(conf, remove_comments=False)) == ["#comment", "data1 #data1", "data2", "data3"]


def test_format_line():
    data = dict(foo="bar baz")
    assert format_line("", data) == ""
    assert format_line("{foo}", data) == "bar baz"
    assert format_line("foo{foo}foo", data) == "foobar bazfoo"


def test_format_line_erroneous():
    data = dict()
    with pytest.raises(PlaceholderError):
        assert format_line("{invalid}", data)
    with pytest.raises(PlaceholderError):
        assert format_line("{}", data)
    with pytest.raises(PlaceholderError):
        assert format_line("{now!r}", data)
    with pytest.raises(PlaceholderError):
        assert format_line("{now.__class__.__module__.__builtins__}", data)


@pytest.mark.parametrize("formatter", (ArchiveFormatter, DiffFormatter, ItemFormatter))
def test_validate_format(formatter):
    formatter.validate_format("")
    formatter.validate_format("{NL}{TAB}")
    for key in formatter.known_keys():
        formatter.validate_format("{" + key + "}")
    with pytest.raises(CommandError, match="Invalid format keys: nosuchkey"):
        formatter.validate_format("{nosuchkey}")
    with pytest.raises(CommandError, match="Invalid format string"):
        formatter.validate_format("{NL")


def test_validate_format_item_hashes():
    # the hash keys are only in KEY_GROUPS, not in KEY_DESCRIPTIONS, see known_keys()
    for key in ("blake3", "md5", "sha256"):
        assert key in ItemFormatter.known_keys()
        ItemFormatter.validate_format("{" + key + "} {path}{NL}")


def test_replace_placeholders():
    replace_placeholders.reset()  # avoid overrides are spoiled by previous tests
    now = datetime.now()
    assert " " not in replace_placeholders("{now}")
    assert int(replace_placeholders("{now:%Y}")) == now.year


def test_override_placeholders():
    assert replace_placeholders("{uuid4}", overrides={"uuid4": "overridden"}) == "overridden"


def working_swidth():
    from ...platform import swidth

    return swidth("선") == 2


@pytest.mark.skipif(not working_swidth(), reason="swidth() is not supported / active")
def test_swidth_slice():
    string = "나윤선나윤선나윤선나윤선나윤선"
    assert swidth_slice(string, 1) == ""
    assert swidth_slice(string, -1) == ""
    assert swidth_slice(string, 4) == "나윤"
    assert swidth_slice(string, -4) == "윤선"


@pytest.mark.skipif(not working_swidth(), reason="swidth() is not supported / active")
def test_swidth_slice_mixed_characters():
    string = "나윤a선나윤선나윤선나윤선나윤선"
    assert swidth_slice(string, 5) == "나윤a"
    assert swidth_slice(string, 6) == "나윤a"


def test_eval_escapes():
    assert eval_escapes("\\n") == "\n"
    assert eval_escapes("\\t") == "\t"
    assert eval_escapes("\\r") == "\r"
    assert eval_escapes("\\f") == "\f"
    assert eval_escapes("\\b") == "\b"
    assert eval_escapes("\\a") == "\a"
    assert eval_escapes("\\v") == "\v"
    assert eval_escapes("\\\\") == "\\"
    assert eval_escapes('\\"') == '"'
    assert eval_escapes("\\'") == "'"
    assert eval_escapes("\\101") == "A"  # ord('A') == 65 == 0o101
    assert eval_escapes("\\x41") == "A"  # ord('A') == 65 == 0x41
    assert eval_escapes("\\u0041") == "A"  # ord('A') == 65 == 0x41
    assert eval_escapes("\\U00000041") == "A"  # ord('A') == 65 == 0x41
    assert eval_escapes("äç\\n") == "äç\n"


@pytest.mark.parametrize(
    "chunker_params, expected_return",
    [
        ("default", ("fastcdc", 19, 23, 21, 2)),
        ("19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("buzhash,19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("10,23,16,4095", ("buzhash", 10, 23, 16, 4095)),
        ("buzhash64,19,23,21,4095,2", ("buzhash64", 19, 23, 21, 4095, 2)),
        ("fastcdc,19,23,21,2", ("fastcdc", 19, 23, 21, 2)),
        ("fixed,4096", ("fixed", 4096, 0)),
        ("fixed,4096,200", ("fixed", 4096, 200)),
    ],
)
def test_valid_chunkerparams(chunker_params, expected_return):
    assert ChunkerParams(chunker_params) == expected_return


@pytest.mark.parametrize(
    "invalid_chunker_params",
    [
        "crap,1,2,3,4",  # invalid algo
        "buzhash,5,7,6,4095",  # too small min. size
        "buzhash,19,24,21,4095",  # too big max. size
        "buzhash,23,19,21,4095",  # violates min <= mask <= max
        "buzhash,19,23,21,4096",  # even window size
        "buzhash,19,23,21",  # missing window_size (must not fall into old-style compat mode)
        "buzhash64,20,20,20,4095,2",  # window_size + 2^chunk_min + 1 > 2^chunk_max
        "buzhash64,19,19,19,4095,2",  # dito, chunk_min == chunk_max
        "buzhash64,19,23,21,4095",  # missing nc_level
        "fastcdc,20,20,20,2",  # chunk_min == chunk_max
        "fastcdc,19,23,21",  # missing nc_level (must not fall into old-style compat mode)
        "fixed,63",  # too small block size
        "fixed,%d,%d" % (MAX_DATA_SIZE + 1, 4096),  # too big block size
        "fixed,%d,%d" % (4096, MAX_DATA_SIZE + 1),  # too big header size
    ],
)
def test_invalid_chunkerparams(invalid_chunker_params):
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(invalid_chunker_params)


@pytest.mark.parametrize(
    "mode, expected_mode, expected_changed",
    [
        # ctime based modes get replaced by their mtime based equivalent:
        ("ctime,size,inode", "ims", True),
        ("cis", "ims", True),
        ("ctime,size", "ms", True),
        ("cs", "ms", True),
        ("rechunk,ctime", "mr", True),
        ("cr", "mr", True),
        # everything else stays as it is (but is normalized to the short form):
        ("mtime,size,inode", "ims", False),
        ("ims", "ims", False),
        ("mtime,size", "ms", False),
        ("rechunk,mtime", "mr", False),
        ("disabled", "d", False),
        ("d", "d", False),
    ],
)
def test_files_cache_mode_no_ctime(mode, expected_mode, expected_changed):
    assert files_cache_mode_no_ctime(mode) == (expected_mode, expected_changed)


def test_files_cache_mode_ui_default():
    # borg create must not default to a ctime based files cache mode on Windows, see #7193.
    assert FILES_CACHE_MODE_UI_DEFAULT_POSIX == "ctime,size,inode"
    assert FILES_CACHE_MODE_UI_DEFAULT_WIN32 == "mtime,size,inode"


@pytest.mark.parametrize(
    "env_value, expect_newlines",
    [
        (None, True),  # default indent=4
        ("none", False),  # compact single-line
        ("0", True),  # newlines only, no spaces
        ("4", True),  # explicit pretty-print
        ("", True),  # empty string, newlines only
        ("\t", True),  # tab indent string
    ],
)
def test_json_dump_indent(monkeypatch, env_value, expect_newlines):
    from ...helpers.parseformat import json_dump

    obj = {"key": "value", "number": 42}
    if env_value is not None:
        monkeypatch.setenv("BORG_JSON_INDENT", env_value)
    else:
        monkeypatch.delenv("BORG_JSON_INDENT", raising=False)

    result = json_dump(obj)
    if expect_newlines:
        assert "\n" in result
    else:
        assert "\n" not in result
    assert json.loads(result) == obj


def test_digest_algos():
    assert DigestAlgos("blake3") == ("blake3",)
    assert DigestAlgos("sha256,blake3") == ("blake3", "sha256")  # sorted and deduplicated
    assert DigestAlgos("blake3,blake3") == ("blake3",)
    assert DigestAlgos("none") == ()
    assert DigestAlgos(("blake3",)) == ("blake3",)  # the default value comes in as a tuple
    for invalid in ("nosuchhash", "blake3,nosuchhash", "shake_128", ""):
        with pytest.raises(ArgumentTypeError):
            DigestAlgos(invalid)


@pytest.mark.parametrize(
    "ctime1_ns, ctime2_ns",
    [
        (1000000000_000123_000, 1000000000_000456_000),  # same second, different microsecond
        (1000000000_000123_000, 1000000001_000123_000),  # different second
    ],
)
def test_diff_formatter_time_precision(ctime1_ns, ctime2_ns):
    """DiffFormatter renders time changes with microsecond precision, so that timestamps
    differing at sub-second level (e.g. hardlink ctime updates, see #9147) are distinguishable."""
    item1 = Item(path="p", mode=0o100644, mtime=0, ctime=ctime1_ns)
    item2 = Item(path="p", mode=0o100644, mtime=0, ctime=ctime2_ns)
    diff = ItemDiff("p", item1, item2, iter([]), iter([]), can_compare_chunk_ids=True)
    formatter = DiffFormatter("{ctime} {path}{NL}")
    output = formatter.format_item(diff)
    m = re.search(r"\[ctime: (.+?) -> (.+?)\]", output)
    assert m is not None
    assert "." in m.group(1) and "." in m.group(2)  # microseconds are shown
    assert m.group(1) != m.group(2)  # timestamps are distinguishable
