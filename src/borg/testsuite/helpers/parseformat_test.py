import base64
import os
from argparse import ArgumentTypeError
from datetime import datetime, timezone

import pytest

from ...constants import *  # NOQA
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
)
from ...helpers.time import format_timedelta, parse_timestamp


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
            repr(Location("ssh://user@host:1234//absolute/path"))
            == "Location(proto='ssh', user='user', host='host', port=1234, path='/absolute/path')"
        )
        assert Location("ssh://user@host:1234//absolute/path").to_key_filename() == keys_dir + "host___absolute_path"
        assert (
            repr(Location("ssh://user@host:1234/relative/path"))
            == "Location(proto='ssh', user='user', host='host', port=1234, path='relative/path')"
        )
        assert Location("ssh://user@host:1234/relative/path").to_key_filename() == keys_dir + "host__relative_path"
        assert (
            repr(Location("ssh://user@host/relative/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[::]:1234/relative/path"))
            == "Location(proto='ssh', user='user', host='::', port=1234, path='relative/path')"
        )
        assert Location("ssh://user@[::]:1234/relative/path").to_key_filename() == keys_dir + "____relative_path"
        assert (
            repr(Location("ssh://user@[::]/relative/path"))
            == "Location(proto='ssh', user='user', host='::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]:1234/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::', port=1234, path='relative/path')"
        )
        assert (
            Location("ssh://user@[2001:db8::]:1234/relative/path").to_key_filename()
            == keys_dir + "2001_db8____relative_path"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::]/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]:1234/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::c0:ffee]/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]:1234/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=1234, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2001:db8::192.0.2.1]/relative/path"))
            == "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=None, path='relative/path')"
        )
        assert (
            Location("ssh://user@[2001:db8::192.0.2.1]/relative/path").to_key_filename()
            == keys_dir + "2001_db8__192_0_2_1__relative_path"
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]/relative/path"))
            == "Location(proto='ssh', user='user', "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=None, path='relative/path')"
        )
        assert (
            repr(Location("ssh://user@[2a02:0001:0002:0003:0004:0005:0006:0007]:1234/relative/path"))
            == "Location(proto='ssh', user='user', "
            "host='2a02:0001:0002:0003:0004:0005:0006:0007', port=1234, path='relative/path')"
        )

    def test_rclone(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("rclone:remote:path"))
            == "Location(proto='rclone', user=None, host=None, port=None, path='remote:path')"
        )
        assert Location("rclone:remote:path").to_key_filename() == keys_dir + "remote_path"

    def test_sftp(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        # relative path
        assert (
            repr(Location("sftp://user@host:1234/rel/path"))
            == "Location(proto='sftp', user='user', host='host', port=1234, path='rel/path')"
        )
        assert Location("sftp://user@host:1234/rel/path").to_key_filename() == keys_dir + "host__rel_path"
        # absolute path
        assert (
            repr(Location("sftp://user@host:1234//abs/path"))
            == "Location(proto='sftp', user='user', host='host', port=1234, path='/abs/path')"
        )
        assert Location("sftp://user@host:1234//abs/path").to_key_filename() == keys_dir + "host___abs_path"

    def test_socket(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("socket:///repo/path"))
            == "Location(proto='socket', user=None, host=None, port=None, path='/repo/path')"
        )
        assert Location("socket:///some/path").to_key_filename() == keys_dir + "_some_path"

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
        assert Location("file:///some/path").to_key_filename() == keys_dir + "_some_path"

    def test_smb(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("file:////server/share/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='//server/share/path')"
        )
        assert Location("file:////server/share/path").to_key_filename() == keys_dir + "__server_share_path"

    def test_folder(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        rel_path = "path"
        abs_path = os.path.abspath(rel_path)
        assert repr(Location(rel_path)) == f"Location(proto='file', user=None, host=None, port=None, path='{abs_path}')"
        assert Location("path").to_key_filename().endswith(rel_path)

    def test_abspath(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/some/absolute/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path')"
        )
        assert Location("/some/absolute/path").to_key_filename() == keys_dir + "_some_absolute_path"
        assert (
            repr(Location("/some/../absolute/path"))
            == "Location(proto='file', user=None, host=None, port=None, path='/absolute/path')"
        )
        assert Location("/some/../absolute/path").to_key_filename() == keys_dir + "_absolute_path"

    def test_relpath(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        # for a local path, borg creates a Location instance with an absolute path
        rel_path = "relative/path"
        abs_path = os.path.abspath(rel_path)
        assert repr(Location(rel_path)) == f"Location(proto='file', user=None, host=None, port=None, path='{abs_path}')"
        assert Location(rel_path).to_key_filename().endswith("relative_path")
        assert (
            repr(Location("ssh://user@host/relative/path"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='relative/path')"
        )
        assert Location("ssh://user@host/relative/path").to_key_filename() == keys_dir + "host__relative_path"

    def test_with_colons(self, monkeypatch, keys_dir):
        monkeypatch.delenv("BORG_REPO", raising=False)
        assert (
            repr(Location("/abs/path:w:cols"))
            == "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols')"
        )
        assert Location("/abs/path:w:cols").to_key_filename() == keys_dir + "_abs_path_w_cols"
        assert (
            repr(Location("file:///abs/path:w:cols"))
            == "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols')"
        )
        assert Location("file:///abs/path:w:cols").to_key_filename() == keys_dir + "_abs_path_w_cols"
        assert (
            repr(Location("ssh://user@host/abs/path:w:cols"))
            == "Location(proto='ssh', user='user', host='host', port=None, path='abs/path:w:cols')"
        )
        assert Location("ssh://user@host/abs/path:w:cols").to_key_filename() == keys_dir + "host__abs_path_w_cols"

    def test_canonical_path(self, monkeypatch):
        monkeypatch.delenv("BORG_REPO", raising=False)
        locations = [
            "relative/path",
            "/absolute/path",
            "file:///absolute/path",
            "socket:///absolute/path",
            "ssh://host/relative/path",
            "ssh://host//absolute/path",
            "ssh://user@host:1234/relative/path",
            "sftp://host/relative/path",
            "sftp://host//absolute/path",
            "sftp://user@host:1234/relative/path",
            "rclone:remote:path",
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
    assert archivename_validator(name) == name


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
    assert text_validator(name="text", max_length=100)(text) == text


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
        ("5S", 5),
        ("2M", 2 * 60),
        ("1H", 60 * 60),
        ("1d", 24 * 60 * 60),
        ("1w", 7 * 24 * 60 * 60),
        ("1m", 31 * 24 * 60 * 60),
        ("1y", 365 * 24 * 60 * 60),
    ],
)
def test_interval(timeframe, num_secs):
    assert interval(timeframe) == num_secs


@pytest.mark.parametrize(
    "invalid_interval, error_tuple",
    [
        ("H", ('Invalid number "": expected positive integer',)),
        ("-1d", ('Invalid number "-1": expected positive integer',)),
        ("food", ('Invalid number "foo": expected positive integer',)),
    ],
)
def test_interval_time_unit(invalid_interval, error_tuple):
    with pytest.raises(ArgumentTypeError) as exc:
        interval(invalid_interval)
    assert exc.value.args == error_tuple


def test_interval_number():
    with pytest.raises(ArgumentTypeError) as exc:
        interval("5")
    assert exc.value.args == ('Unexpected time unit "5": choose from y, m, w, d, H, M, S',)


def test_parse_timestamp():
    assert parse_timestamp("2015-04-19T20:25:00.226410") == datetime(2015, 4, 19, 20, 25, 0, 226410, timezone.utc)
    assert parse_timestamp("2015-04-19T20:25:00") == datetime(2015, 4, 19, 20, 25, 0, 0, timezone.utc)


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
        "buzhash,19,23,21,4096",  # even window size
        "fixed,63",  # too small block size
        "fixed,%d,%d" % (MAX_DATA_SIZE + 1, 4096),  # too big block size
        "fixed,%d,%d" % (4096, MAX_DATA_SIZE + 1),  # too big header size
    ],
)
def test_invalid_chunkerparams(invalid_chunker_params):
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(invalid_chunker_params)
