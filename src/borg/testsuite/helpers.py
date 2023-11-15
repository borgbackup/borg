import base64
import errno
import getpass
import hashlib
import os
import shutil
import sys
from argparse import ArgumentTypeError
from datetime import datetime, timezone, timedelta
from io import StringIO, BytesIO

import pytest

from ..archiver.prune_cmd import prune_within, prune_split
from .. import platform
from ..constants import *  # NOQA
from ..helpers import Location
from ..helpers import Buffer
from ..helpers import (
    partial_format,
    format_file_size,
    parse_file_size,
    format_timedelta,
    format_line,
    PlaceholderError,
    replace_placeholders,
)
from ..helpers import remove_dotdot_prefixes, make_path_safe, clean_lines
from ..helpers import interval
from ..helpers import get_base_dir, get_cache_dir, get_keys_dir, get_security_dir, get_config_dir, get_runtime_dir
from ..helpers import is_slow_msgpack
from ..helpers import msgpack
from ..helpers import yes, TRUISH, FALSISH, DEFAULTISH
from ..helpers import StableDict, bin_to_hex
from ..helpers import parse_timestamp, ChunkIteratorFileWrapper, ChunkerParams
from ..helpers import archivename_validator, text_validator
from ..helpers import ProgressIndicatorPercent
from ..helpers import swidth_slice
from ..helpers import chunkit
from ..helpers import safe_ns, safe_s, SUPPORT_32BIT_PLATFORMS
from ..helpers import popen_with_error_handling
from ..helpers import dash_open
from ..helpers import iter_separated
from ..helpers import eval_escapes
from ..helpers import safe_unlink
from ..helpers import text_to_json, binary_to_json
from ..helpers import classify_ec, max_ec
from ..helpers.passphrase import Passphrase, PasswordRetriesExceeded
from ..platform import is_cygwin, is_win32, is_darwin
from . import FakeInputs, are_hardlinks_supported
from . import rejected_dotdot_paths


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
        # no surrogate-escapes, just unicode text
        assert key in d
        assert d[key] == value_b.decode("utf-8", errors="strict")
        assert d[key].encode("utf-8", errors="strict") == value_b
        assert key_b64 not in d  # not needed. pure valid unicode.
    else:
        # requiring surrogate-escapes. text has replacement chars, base64 representation is present.
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
            repr(Location("ssh://user@host:1234/some/path"))
            == "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path')"
        )
        assert Location("ssh://user@host:1234/some/path").to_key_filename() == keys_dir + "host__some_path"
        assert (
            repr(Location("ssh://user@host:1234/some/path"))
            == "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@host/some/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[::]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='::', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[::]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='::', port=1234, path='/some/path')"
        )
        assert Location("ssh://user@[::]:1234/some/path").to_key_filename() == keys_dir + "____some_path"
        assert (
            repr(Location("ssh://user@[::]/some/path"))
            == "Location(proto='ssh', user='user', host='::', port=None, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::', port=1234, path='/some/path')"
        )
        assert (
            Location("ssh://user@[2001:db8::]:1234/some/path").to_key_filename() == keys_dir + "2001_db8____some_path"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::', port=None, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=None, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]:1234/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=1234, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]/some/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=None, path='/some/path')"
        )
        assert (
            Location("ssh://user@[2001:db8::192.0.2.1]/some/path").to_key_filename()
            == keys_dir + "2001_db8__192_0_2_1__some_path"
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]/some/path"))
            == "Location(proto='ssh', user='user', "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=None, path='/some/path')"
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]:1234/some/path"))
            == "Location(proto='ssh', user='user', "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=1234, path='/some/path')"
        )

    def test_socket(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("socket:///repo/path"))
            == "Location(proto='socket', user=None, host=None, port=None, path='/repo/path')"
        )
        assert Location("socket:///some/path").to_key_filename() == keys_dir + "some_path"

    def test_file(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("file:///some/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/some/path')"
        )
        assert (
            repr(Location("file:///some/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/some/path')"
        )
        assert Location("file:///some/path").to_key_filename() == keys_dir + "some_path"

    def test_smb(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("file:////server/share/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='//server/share/path')"
        )
        assert Location("file:////server/share/path").to_key_filename() == keys_dir + "server_share_path"

    def test_folder(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert repr(Location("path")) == "Location(proto='file', user=None, host=None, port=None, path='path')"
        assert Location("path").to_key_filename() == keys_dir + "path"

    def test_long_path(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert Location(os.path.join(*(40 * ["path"]))).to_key_filename() == keys_dir + "_".join(20 * ["path"]) + "_"

    def test_abspath(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/some/absolute/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path')"
        )
        assert (
            repr(Location("/some/absolute/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path')"
        )
        assert Location("/some/absolute/path").to_key_filename() == keys_dir + "some_absolute_path"
        assert (
            repr(Location("ssh://user@host/some/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='/some/path')"
        )
        assert Location("ssh://user@host/some/path").to_key_filename() == keys_dir + "host__some_path"

    def test_relpath(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("some/relative/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='some/relative/path')"
        )
        assert (
            repr(Location("some/relative/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='some/relative/path')"
        )
        assert Location("some/relative/path").to_key_filename() == keys_dir + "some_relative_path"
        assert (
            repr(Location("ssh://user@host/./some/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='/./some/path')"
        )
        assert Location("ssh://user@host/./some/path").to_key_filename() == keys_dir + "host__some_path"
        assert (
            repr(Location("ssh://user@host/~/some/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='/~/some/path')"
        )
        assert Location("ssh://user@host/~/some/path").to_key_filename() == keys_dir + "host__some_path"

    def test_with_colons(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/abs/path:w:cols"))
            == "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols')"
        )
        assert (
            repr(Location("/abs/path:with:colons"))
            == "Location(proto='file', user=None, host=None, port=None, path='/abs/path:with:colons')"
        )
        assert (
            repr(Location("/abs/path:with:colons"))
            == "Location(proto='file', user=None, host=None, port=None, path='/abs/path:with:colons')"
        )
        assert Location("/abs/path:with:colons").to_key_filename() == keys_dir + "abs_path_with_colons"

    def test_canonical_path(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        locations = [
            "some/path",
            "file://some/path",
            "host:some/path",
            "host:~user/some/path",
            "socket:///some/path",
            "ssh://host/some/path",
            "ssh://user@host:1234/some/path",
        ]
        for location in locations:
            assert (
                Location(location).canonical_path() == Location(Location(location).canonical_path()).canonical_path()
            ), ("failed: %s" % location)

    def test_bad_syntax(self):
        with pytest.raises(ValueError):
            # this is invalid due to the 2nd colon, correct: 'ssh://user@host/path'
            Location("ssh://user@host:/path")


@pytest.mark.parametrize(
    "name",
    [
        "foobar",
        # placeholders
        "foobar-{now}",
    ],
)
def test_archivename_ok(name):
    archivename_validator(name)  # must not raise an exception


@pytest.mark.parametrize(
    "name",
    [
        "",  # too short
        "x" * 201,  # too long
        # invalid chars:
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
        # leading/trailing blanks
        " foo",
        "bar  ",
        # contains surrogate-escapes
        "foo\udc80bar",
        "foo\udcffbar",
    ],
)
def test_archivename_invalid(name):
    with pytest.raises(ArgumentTypeError):
        archivename_validator(name)


@pytest.mark.parametrize("text", ["", "single line", "multi\nline\ncomment"])
def test_text_ok(text):
    tv = text_validator(max_length=100, name="name")
    tv(text)  # must not raise an exception


@pytest.mark.parametrize(
    "text",
    [
        "x" * 101,  # too long
        # invalid chars:
        "foo\0bar",
        # contains surrogate-escapes
        "foo\udc80bar",
        "foo\udcffbar",
    ],
)
def test_text_invalid(text):
    tv = text_validator(max_length=100, name="name")
    with pytest.raises(ArgumentTypeError):
        tv(text)


def test_format_timedelta():
    t0 = datetime(2001, 1, 1, 10, 20, 3, 0)
    t1 = datetime(2001, 1, 1, 12, 20, 4, 100000)
    assert format_timedelta(t1 - t0) == "2 hours 1.10 seconds"


@pytest.mark.parametrize(
    "chunker_params, expected_return",
    [
        ("default", ("buzhash", 19, 23, 21, 4095)),
        ("19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("buzhash,19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("10,23,16,4095", ("buzhash", 10, 23, 16, 4095)),
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
        "fixed,63",  # too small block size
        "fixed,%d,%d" % (MAX_DATA_SIZE + 1, 4096),  # too big block size
        "fixed,%d,%d" % (4096, MAX_DATA_SIZE + 1),  # too big header size
    ],
)
def test_invalid_chunkerparams(invalid_chunker_params):
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(invalid_chunker_params)


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


class MockArchive:
    def __init__(self, ts, id):
        self.ts = ts
        self.id = id

    def __repr__(self):
        return f"{self.id}: {self.ts.isoformat()}"


# This is the local timezone of the system running the tests.
# We need this e.g. to construct archive timestamps for the prune tests,
# because borg prune operates in the local timezone (it first converts the
# archive timestamp to the local timezone). So, if we want the y/m/d/h/m/s
# values which prune uses to be exactly the ones we give [and NOT shift them
# by tzoffset], we need to give the timestamps in the same local timezone.
# Please note that the timestamps in a real borg archive or manifest are
# stored in UTC timezone.
local_tz = datetime.now(tz=timezone.utc).astimezone(tz=None).tzinfo


@pytest.mark.parametrize(
    "rule,num_to_keep,expected_ids",
    [
        ("yearly", 3, (13, 2, 1)),
        ("monthly", 3, (13, 8, 4)),
        ("weekly", 2, (13, 8)),
        ("daily", 3, (13, 8, 7)),
        ("hourly", 3, (13, 10, 8)),
        ("minutely", 3, (13, 10, 9)),
        ("secondly", 4, (13, 12, 11, 10)),
        ("daily", 0, []),
    ],
)
def test_prune_split(rule, num_to_keep, expected_ids):
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # years apart
        MockArchive(datetime(2015, 1, 1, 10, 0, 0, tzinfo=local_tz), 1),
        MockArchive(datetime(2016, 1, 1, 10, 0, 0, tzinfo=local_tz), 2),
        MockArchive(datetime(2017, 1, 1, 10, 0, 0, tzinfo=local_tz), 3),
        # months apart
        MockArchive(datetime(2017, 2, 1, 10, 0, 0, tzinfo=local_tz), 4),
        MockArchive(datetime(2017, 3, 1, 10, 0, 0, tzinfo=local_tz), 5),
        # days apart
        MockArchive(datetime(2017, 3, 2, 10, 0, 0, tzinfo=local_tz), 6),
        MockArchive(datetime(2017, 3, 3, 10, 0, 0, tzinfo=local_tz), 7),
        MockArchive(datetime(2017, 3, 4, 10, 0, 0, tzinfo=local_tz), 8),
        # minutes apart
        MockArchive(datetime(2017, 10, 1, 9, 45, 0, tzinfo=local_tz), 9),
        MockArchive(datetime(2017, 10, 1, 9, 55, 0, tzinfo=local_tz), 10),
        # seconds apart
        MockArchive(datetime(2017, 10, 1, 10, 0, 1, tzinfo=local_tz), 11),
        MockArchive(datetime(2017, 10, 1, 10, 0, 3, tzinfo=local_tz), 12),
        MockArchive(datetime(2017, 10, 1, 10, 0, 5, tzinfo=local_tz), 13),
    ]
    kept_because = {}
    keep = prune_split(archives, rule, num_to_keep, kept_because)

    assert set(keep) == subset(archives, expected_ids)
    for item in keep:
        assert kept_because[item.id][0] == rule


def test_prune_split_keep_oldest():
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # oldest backup, but not last in its year
        MockArchive(datetime(2018, 1, 1, 10, 0, 0, tzinfo=local_tz), 1),
        # an interim backup
        MockArchive(datetime(2018, 12, 30, 10, 0, 0, tzinfo=local_tz), 2),
        # year-end backups
        MockArchive(datetime(2018, 12, 31, 10, 0, 0, tzinfo=local_tz), 3),
        MockArchive(datetime(2019, 12, 31, 10, 0, 0, tzinfo=local_tz), 4),
    ]

    # Keep oldest when retention target can't otherwise be met
    kept_because = {}
    keep = prune_split(archives, "yearly", 3, kept_because)

    assert set(keep) == subset(archives, [1, 3, 4])
    assert kept_because[1][0] == "yearly[oldest]"
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"

    # Otherwise, prune it
    kept_because = {}
    keep = prune_split(archives, "yearly", 2, kept_because)

    assert set(keep) == subset(archives, [3, 4])
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"


def test_prune_split_no_archives():
    archives = []

    kept_because = {}
    keep = prune_split(archives, "yearly", 3, kept_because)

    assert keep == []
    assert kept_because == {}


@pytest.mark.parametrize("timeframe, num_hours", [("1H", 1), ("1d", 24), ("1w", 168), ("1m", 744), ("1y", 8760)])
def test_interval(timeframe, num_hours):
    assert interval(timeframe) == num_hours


@pytest.mark.parametrize(
    "invalid_interval, error_tuple",
    [
        ("H", ('Unexpected interval number "": expected an integer greater than 0',)),
        ("-1d", ('Unexpected interval number "-1": expected an integer greater than 0',)),
        ("food", ('Unexpected interval number "foo": expected an integer greater than 0',)),
    ],
)
def test_interval_time_unit(invalid_interval, error_tuple):
    with pytest.raises(ArgumentTypeError) as exc:
        interval(invalid_interval)
    assert exc.value.args == error_tuple


def test_interval_number():
    with pytest.raises(ArgumentTypeError) as exc:
        interval("5")
    assert exc.value.args == ("Unexpected interval time unit \"5\": expected one of ['H', 'd', 'w', 'm', 'y']",)


def test_prune_within():
    def subset(lst, indices):
        return {lst[i] for i in indices}

    def dotest(test_archives, within, indices):
        for ta in test_archives, reversed(test_archives):
            kept_because = {}
            keep = prune_within(ta, interval(within), kept_because)
            assert set(keep) == subset(test_archives, indices)
            assert all("within" == kept_because[a.id][0] for a in keep)

    # 1 minute, 1.5 hours, 2.5 hours, 3.5 hours, 25 hours, 49 hours
    test_offsets = [60, 90 * 60, 150 * 60, 210 * 60, 25 * 60 * 60, 49 * 60 * 60]
    now = datetime.now(timezone.utc)
    test_dates = [now - timedelta(seconds=s) for s in test_offsets]
    test_archives = [MockArchive(date, i) for i, date in enumerate(test_dates)]

    dotest(test_archives, "1H", [0])
    dotest(test_archives, "2H", [0, 1])
    dotest(test_archives, "3H", [0, 1, 2])
    dotest(test_archives, "24H", [0, 1, 2, 3])
    dotest(test_archives, "26H", [0, 1, 2, 3, 4])
    dotest(test_archives, "2d", [0, 1, 2, 3, 4])
    dotest(test_archives, "50H", [0, 1, 2, 3, 4, 5])
    dotest(test_archives, "3d", [0, 1, 2, 3, 4, 5])
    dotest(test_archives, "1w", [0, 1, 2, 3, 4, 5])
    dotest(test_archives, "1m", [0, 1, 2, 3, 4, 5])
    dotest(test_archives, "1y", [0, 1, 2, 3, 4, 5])


def test_stable_dict():
    d = StableDict(foo=1, bar=2, boo=3, baz=4)
    assert list(d.items()) == [("bar", 2), ("baz", 4), ("boo", 3), ("foo", 1)]
    assert hashlib.md5(msgpack.packb(d)).hexdigest() == "fc78df42cd60691b3ac3dd2a2b39903f"


def test_parse_timestamp():
    assert parse_timestamp("2015-04-19T20:25:00.226410") == datetime(2015, 4, 19, 20, 25, 0, 226410, timezone.utc)
    assert parse_timestamp("2015-04-19T20:25:00") == datetime(2015, 4, 19, 20, 25, 0, 0, timezone.utc)


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


@pytest.mark.parametrize(
    "size, fmt",
    [
        (0, "0 B"),  # no rounding necessary for those
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
        (999995000, "1.00 GB"),  # rounded up to next unit
        (10**6, "1.00 MB"),  # and all the remaining units, megabytes
        (10**9, "1.00 GB"),  # gigabytes
        (10**12, "1.00 TB"),  # terabytes
        (10**15, "1.00 PB"),  # petabytes
        (10**18, "1.00 EB"),  # exabytes
        (10**21, "1.00 ZB"),  # zottabytes
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
def test_file_size_iec(size, fmt):
    """test the size formatting routines"""
    assert format_file_size(size, iec=True) == fmt


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
    "string, value", [("1", 1), ("20", 20), ("5K", 5000), ("1.75M", 1750000), ("1e+9", 1e9), ("-1T", -1e12)]
)
def test_parse_file_size(string, value):
    assert parse_file_size(string) == int(value)


@pytest.mark.parametrize("string", ("", "5 Äpfel", "4E", "2229 bit", "1B"))
def test_parse_file_size_invalid(string):
    with pytest.raises(ValueError):
        parse_file_size(string)


def expected_py_mp_slow_combination():
    """do we expect msgpack to be slow in this environment?"""
    # we need to import upstream msgpack package here, not helpers.msgpack:
    import msgpack

    # msgpack is slow on cygwin
    if is_cygwin:
        return True
    # msgpack < 1.0.6 did not have py312 wheels
    if sys.version_info[:2] == (3, 12) and msgpack.version < (1, 0, 6):
        return True
    # otherwise we expect msgpack to be fast!
    return False


@pytest.mark.skipif(expected_py_mp_slow_combination(), reason="ignore expected slow msgpack")
def test_is_slow_msgpack():
    # we need to import upstream msgpack package here, not helpers.msgpack:
    import msgpack
    import msgpack.fallback

    saved_packer = msgpack.Packer
    try:
        msgpack.Packer = msgpack.fallback.Packer
        assert is_slow_msgpack()
    finally:
        msgpack.Packer = saved_packer
    # this tests that we have fast msgpack on test platform:
    assert not is_slow_msgpack()


class TestBuffer:
    def test_type(self):
        buffer = Buffer(bytearray)
        assert isinstance(buffer.get(), bytearray)
        buffer = Buffer(bytes)  # don't do that in practice
        assert isinstance(buffer.get(), bytes)

    def test_len(self):
        buffer = Buffer(bytearray, size=0)
        b = buffer.get()
        assert len(buffer) == len(b) == 0
        buffer = Buffer(bytearray, size=1234)
        b = buffer.get()
        assert len(buffer) == len(b) == 1234

    def test_resize(self):
        buffer = Buffer(bytearray, size=100)
        assert len(buffer) == 100
        b1 = buffer.get()
        buffer.resize(200)
        assert len(buffer) == 200
        b2 = buffer.get()
        assert b2 is not b1  # new, bigger buffer
        buffer.resize(100)
        assert len(buffer) >= 100
        b3 = buffer.get()
        assert b3 is b2  # still same buffer (200)
        buffer.resize(100, init=True)
        assert len(buffer) == 100  # except on init
        b4 = buffer.get()
        assert b4 is not b3  # new, smaller buffer

    def test_limit(self):
        buffer = Buffer(bytearray, size=100, limit=200)
        buffer.resize(200)
        assert len(buffer) == 200
        with pytest.raises(Buffer.MemoryLimitExceeded):
            buffer.resize(201)
        assert len(buffer) == 200

    def test_get(self):
        buffer = Buffer(bytearray, size=100, limit=200)
        b1 = buffer.get(50)
        assert len(b1) >= 50  # == 100
        b2 = buffer.get(100)
        assert len(b2) >= 100  # == 100
        assert b2 is b1  # did not need resizing yet
        b3 = buffer.get(200)
        assert len(b3) == 200
        assert b3 is not b2  # new, resized buffer
        with pytest.raises(Buffer.MemoryLimitExceeded):
            buffer.get(201)  # beyond limit
        assert len(buffer) == 200


def test_yes_input():
    inputs = list(TRUISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert yes(input=input)
    inputs = list(FALSISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert not yes(input=input)


def test_yes_input_defaults():
    inputs = list(DEFAULTISH)
    input = FakeInputs(inputs)
    for i in inputs:
        assert yes(default=True, input=input)
    input = FakeInputs(inputs)
    for i in inputs:
        assert not yes(default=False, input=input)


def test_yes_input_custom():
    input = FakeInputs(["YES", "SURE", "NOPE"])
    assert yes(truish=("YES",), input=input)
    assert yes(truish=("SURE",), input=input)
    assert not yes(falsish=("NOPE",), input=input)


def test_yes_env(monkeypatch):
    for value in TRUISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert yes(env_var_override="OVERRIDE_THIS")
    for value in FALSISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert not yes(env_var_override="OVERRIDE_THIS")


def test_yes_env_default(monkeypatch):
    for value in DEFAULTISH:
        monkeypatch.setenv("OVERRIDE_THIS", value)
        assert yes(env_var_override="OVERRIDE_THIS", default=True)
        assert not yes(env_var_override="OVERRIDE_THIS", default=False)


def test_yes_defaults():
    input = FakeInputs(["invalid", "", " "])
    assert not yes(input=input)  # default=False
    assert not yes(input=input)
    assert not yes(input=input)
    input = FakeInputs(["invalid", "", " "])
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    input = FakeInputs([])
    assert yes(default=True, input=input)
    assert not yes(default=False, input=input)
    with pytest.raises(ValueError):
        yes(default=None)


def test_yes_retry():
    input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert yes(retry_msg="Retry: ", input=input)
    input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert not yes(retry_msg="Retry: ", input=input)


def test_yes_no_retry():
    input = FakeInputs(["foo", "bar", TRUISH[0]])
    assert not yes(retry=False, default=False, input=input)
    input = FakeInputs(["foo", "bar", FALSISH[0]])
    assert yes(retry=False, default=True, input=input)


def test_yes_output(capfd):
    input = FakeInputs(["invalid", "y", "n"])
    assert yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=input)
    out, err = capfd.readouterr()
    assert out == ""
    assert "intro-msg" in err
    assert "retry-msg" in err
    assert "true-msg" in err
    assert not yes(msg="intro-msg", false_msg="false-msg", true_msg="true-msg", retry_msg="retry-msg", input=input)
    out, err = capfd.readouterr()
    assert out == ""
    assert "intro-msg" in err
    assert "retry-msg" not in err
    assert "false-msg" in err


def test_yes_env_output(capfd, monkeypatch):
    env_var = "OVERRIDE_SOMETHING"
    monkeypatch.setenv(env_var, "yes")
    assert yes(env_var_override=env_var)
    out, err = capfd.readouterr()
    assert out == ""
    assert env_var in err
    assert "yes" in err


def test_progress_percentage(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show(420)
    pi.show(680)
    out, err = capfd.readouterr()
    assert err == " 42%\n 68%\n"
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == "100%\n"
    pi.finish()
    out, err = capfd.readouterr()
    assert err == "\n"


def test_progress_percentage_step(capfd):
    pi = ProgressIndicatorPercent(100, step=2, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show()
    out, err = capfd.readouterr()
    assert err == ""  # no output at 1% as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  2%\n"


def test_progress_percentage_quiet(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("WARN")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == ""
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == ""
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ""


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


def test_chunk_file_wrapper():
    cfw = ChunkIteratorFileWrapper(iter([b"abc", b"def"]))
    assert cfw.read(2) == b"ab"
    assert cfw.read(50) == b"cdef"
    assert cfw.exhausted

    cfw = ChunkIteratorFileWrapper(iter([]))
    assert cfw.read(2) == b""
    assert cfw.exhausted


def test_chunkit():
    it = chunkit("abcdefg", 3)
    assert next(it) == ["a", "b", "c"]
    assert next(it) == ["d", "e", "f"]
    assert next(it) == ["g"]
    with pytest.raises(StopIteration):
        next(it)
    with pytest.raises(StopIteration):
        next(it)

    it = chunkit("ab", 3)
    assert list(it) == [["a", "b"]]

    it = chunkit("", 3)
    assert list(it) == []


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


def test_replace_placeholders():
    replace_placeholders.reset()  # avoid overrides are spoiled by previous tests
    now = datetime.now()
    assert " " not in replace_placeholders("{now}")
    assert int(replace_placeholders("{now:%Y}")) == now.year


def test_override_placeholders():
    assert replace_placeholders("{uuid4}", overrides={"uuid4": "overridden"}) == "overridden"


def working_swidth():
    return platform.swidth("선") == 2


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


def utcfromtimestamp(timestamp):
    """Returns a naive datetime instance representing the timestamp in the UTC timezone"""
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)


def test_safe_timestamps():
    if SUPPORT_32BIT_PLATFORMS:
        # ns fit into int64
        assert safe_ns(2**64) <= 2**63 - 1
        assert safe_ns(-1) == 0
        # s fit into int32
        assert safe_s(2**64) <= 2**31 - 1
        assert safe_s(-1) == 0
        # datetime won't fall over its y10k problem
        beyond_y10k = 2**100
        with pytest.raises(OverflowError):
            utcfromtimestamp(beyond_y10k)
        assert utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2038, 1, 1)
        assert utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2038, 1, 1)
    else:
        # ns fit into int64
        assert safe_ns(2**64) <= 2**63 - 1
        assert safe_ns(-1) == 0
        # s are so that their ns conversion fits into int64
        assert safe_s(2**64) * 1000000000 <= 2**63 - 1
        assert safe_s(-1) == 0
        # datetime won't fall over its y10k problem
        beyond_y10k = 2**100
        with pytest.raises(OverflowError):
            utcfromtimestamp(beyond_y10k)
        assert utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2262, 1, 1)
        assert utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2262, 1, 1)


class TestPopenWithErrorHandling:
    @pytest.mark.skipif(not shutil.which("test"), reason='"test" binary is needed')
    def test_simple(self):
        proc = popen_with_error_handling("test 1")
        assert proc.wait() == 0

    @pytest.mark.skipif(
        shutil.which("borg-foobar-test-notexist"), reason='"borg-foobar-test-notexist" binary exists (somehow?)'
    )
    def test_not_found(self):
        proc = popen_with_error_handling("borg-foobar-test-notexist 1234")
        assert proc is None

    @pytest.mark.parametrize("cmd", ('mismatched "quote', 'foo --bar="baz', ""))
    def test_bad_syntax(self, cmd):
        proc = popen_with_error_handling(cmd)
        assert proc is None

    def test_shell(self):
        with pytest.raises(AssertionError):
            popen_with_error_handling("", shell=True)


def test_dash_open():
    assert dash_open("-", "r") is sys.stdin
    assert dash_open("-", "w") is sys.stdout
    assert dash_open("-", "rb") is sys.stdin.buffer
    assert dash_open("-", "wb") is sys.stdout.buffer


def test_iter_separated():
    # newline and utf-8
    sep, items = "\n", ["foo", "bar/baz", "αáčő"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd)) == items
    # null and bogus ending
    sep, items = "\0", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items) + "\0")
    assert list(iter_separated(fd, sep=sep)) == ["foo/bar", "baz", "spam"]
    # multichar
    sep, items = "SEP", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd, sep=sep)) == items
    # bytes
    sep, items = b"\n", [b"foo", b"blop\t", b"gr\xe4ezi"]
    fd = BytesIO(sep.join(items))
    assert list(iter_separated(fd)) == items


def test_eval_escapes():
    assert eval_escapes("\\n\\0\\x23") == "\n\0#"
    assert eval_escapes("äç\\n") == "äç\n"


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

    def os_unlink(_):
        raise OSError(errno.ENOSPC, "Pretend that we ran out of space")

    monkeypatch.setattr(os, "unlink", os_unlink)

    with pytest.raises(OSError):
        safe_unlink(hard_link)

    assert victim.read_binary() == contents


class TestPassphrase:
    def test_passphrase_new_verification(self, capsys, monkeypatch):
        monkeypatch.setattr(getpass, "getpass", lambda prompt: "1234aöäü")
        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "no")
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "1234" not in out
        assert "1234" not in err

        monkeypatch.setenv("BORG_DISPLAY_PASSPHRASE", "yes")
        passphrase = Passphrase.new()
        out, err = capsys.readouterr()
        assert "3132333461c3b6c3a4c3bc" not in out
        assert "3132333461c3b6c3a4c3bc" in err
        assert passphrase == "1234aöäü"

        monkeypatch.setattr(getpass, "getpass", lambda prompt: "1234/@=")
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "1234/@=" not in out
        assert "1234/@=" in err

    def test_passphrase_new_empty(self, capsys, monkeypatch):
        monkeypatch.delenv("BORG_PASSPHRASE", False)
        monkeypatch.setattr(getpass, "getpass", lambda prompt: "")
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new(allow_empty=False)
        out, err = capsys.readouterr()
        assert "must not be blank" in err

    def test_passphrase_new_retries(self, monkeypatch):
        monkeypatch.delenv("BORG_PASSPHRASE", False)
        ascending_numbers = iter(range(20))
        monkeypatch.setattr(getpass, "getpass", lambda prompt: str(next(ascending_numbers)))
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new()

    def test_passphrase_repr(self):
        assert "secret" not in repr(Passphrase("secret"))


@pytest.mark.parametrize(
    "ec_range,ec_class",
    (
        # inclusive range start, exclusive range end
        ((0, 1), "success"),
        ((1, 2), "warning"),
        ((2, 3), "error"),
        ((EXIT_ERROR_BASE, EXIT_WARNING_BASE), "error"),
        ((EXIT_WARNING_BASE, EXIT_SIGNAL_BASE), "warning"),
        ((EXIT_SIGNAL_BASE, 256), "signal"),
    ),
)
def test_classify_ec(ec_range, ec_class):
    for ec in range(*ec_range):
        classify_ec(ec) == ec_class


def test_ec_invalid():
    with pytest.raises(ValueError):
        classify_ec(666)
    with pytest.raises(ValueError):
        classify_ec(-1)
    with pytest.raises(TypeError):
        classify_ec(None)


@pytest.mark.parametrize(
    "ec1,ec2,ec_max",
    (
        # same for modern / legacy
        (EXIT_SUCCESS, EXIT_SUCCESS, EXIT_SUCCESS),
        (EXIT_SUCCESS, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # legacy exit codes
        (EXIT_SUCCESS, EXIT_WARNING, EXIT_WARNING),
        (EXIT_SUCCESS, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SUCCESS, EXIT_WARNING),
        (EXIT_WARNING, EXIT_WARNING, EXIT_WARNING),
        (EXIT_WARNING, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR, EXIT_SUCCESS, EXIT_ERROR),
        (EXIT_ERROR, EXIT_WARNING, EXIT_ERROR),
        (EXIT_ERROR, EXIT_ERROR, EXIT_ERROR),
        (EXIT_ERROR, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # some modern codes
        (EXIT_SUCCESS, EXIT_WARNING_BASE, EXIT_WARNING_BASE),
        (EXIT_SUCCESS, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SUCCESS, EXIT_WARNING_BASE),
        (EXIT_WARNING_BASE + 1, EXIT_WARNING_BASE + 2, EXIT_WARNING_BASE + 1),
        (EXIT_WARNING_BASE, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR_BASE, EXIT_SUCCESS, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE, EXIT_WARNING_BASE, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE + 1, EXIT_ERROR_BASE + 2, EXIT_ERROR_BASE + 1),
        (EXIT_ERROR_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
    ),
)
def test_max_ec(ec1, ec2, ec_max):
    assert max_ec(ec1, ec2) == ec_max
