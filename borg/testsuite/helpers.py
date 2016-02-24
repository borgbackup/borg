import hashlib
from time import mktime, strptime
from datetime import datetime, timezone, timedelta
from io import StringIO
import os

import pytest
import sys
import msgpack
import msgpack.fallback
import time

from ..helpers import Location, format_file_size, format_timedelta, make_path_safe, \
    prune_within, prune_split, get_cache_dir, get_keys_dir, Statistics, is_slow_msgpack, \
    yes, TRUISH, FALSISH, DEFAULTISH, \
    StableDict, int_to_bigint, bigint_to_int, parse_timestamp, CompressionSpec, ChunkerParams, \
    ProgressIndicatorPercent, ProgressIndicatorEndless, load_excludes, parse_pattern, \
    PatternMatcher, RegexPattern, PathPrefixPattern, FnmatchPattern, ShellPattern
from . import BaseTestCase, environment_variable, FakeInputs


class BigIntTestCase(BaseTestCase):

    def test_bigint(self):
        self.assert_equal(int_to_bigint(0), 0)
        self.assert_equal(int_to_bigint(2**63-1), 2**63-1)
        self.assert_equal(int_to_bigint(-2**63+1), -2**63+1)
        self.assert_equal(int_to_bigint(2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\x00')
        self.assert_equal(int_to_bigint(-2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\xff')
        self.assert_equal(bigint_to_int(int_to_bigint(-2**70)), -2**70)
        self.assert_equal(bigint_to_int(int_to_bigint(2**70)), 2**70)


class TestLocationWithoutEnv:
    def test_ssh(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('ssh://user@host:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('ssh://user@host:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive=None)"

    def test_file(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('file:///some/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')"
        assert repr(Location('file:///some/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive=None)"

    def test_scp(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('user@host:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@host:/some/path')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"

    def test_folder(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive='archive')"
        assert repr(Location('path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive=None)"

    def test_abspath(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('/some/absolute/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        assert repr(Location('/some/absolute/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive=None)"

    def test_relpath(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('some/relative/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        assert repr(Location('some/relative/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive=None)"

    def test_underspecified(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        with pytest.raises(ValueError):
            Location('::archive')
        with pytest.raises(ValueError):
            Location('::')
        with pytest.raises(ValueError):
            Location()

    def test_no_double_colon(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        with pytest.raises(ValueError):
            Location('ssh://localhost:22/path:archive')

    def test_no_slashes(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        with pytest.raises(ValueError):
            Location('/some/path/to/repo::archive_name_with/slashes/is_invalid')

    def test_canonical_path(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        locations = ['some/path::archive', 'file://some/path::archive', 'host:some/path::archive',
                     'host:~user/some/path::archive', 'ssh://host/some/path::archive',
                     'ssh://user@host:1234/some/path::archive']
        for location in locations:
            assert Location(location).canonical_path() == \
                Location(Location(location).canonical_path()).canonical_path()

    def test_format_path(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        test_pid = os.getpid()
        assert repr(Location('/some/path::archive{pid}')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive{}')".format(test_pid)
        location_time1 = Location('/some/path::archive{now:%s}')
        time.sleep(1.1)
        location_time2 = Location('/some/path::archive{now:%s}')
        assert location_time1.archive != location_time2.archive


class TestLocationWithEnv:
    def test_ssh(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'ssh://user@host:1234/some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive=None)"

    def test_file(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'file:///some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive=None)"

    def test_scp(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'user@host:/some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"

    def test_folder(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive=None)"

    def test_abspath(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', '/some/absolute/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive=None)"

    def test_relpath(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'some/relative/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        assert repr(Location()) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive=None)"

    def test_no_slashes(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', '/some/absolute/path')
        with pytest.raises(ValueError):
            Location('::archive_name_with/slashes/is_invalid')


class FormatTimedeltaTestCase(BaseTestCase):

    def test(self):
        t0 = datetime(2001, 1, 1, 10, 20, 3, 0)
        t1 = datetime(2001, 1, 1, 12, 20, 4, 100000)
        self.assert_equal(
            format_timedelta(t1 - t0),
            '2 hours 1.10 seconds'
        )


def check_patterns(files, pattern, expected):
    """Utility for testing patterns.
    """
    assert all([f == os.path.normpath(f) for f in files]), "Pattern matchers expect normalized input paths"

    matched = [f for f in files if pattern.match(f)]

    assert matched == (files if expected is None else expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("/", None),
    ("/./", None),
    ("", []),
    ("/home/u", []),
    ("/home/user", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc", ["/etc/server/config", "/etc/server/hosts"]),
    ("///etc//////", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv", ["/srv/messages", "/srv/dmesg"]),
    ])
def test_patterns_prefix(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv/messages", "/srv/dmesg",
    ]

    check_patterns(files, PathPrefixPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("", []),
    ("foo", []),
    ("relative", ["relative/path1", "relative/two"]),
    ("more", ["more/relative"]),
    ])
def test_patterns_prefix_relative(pattern, expected):
    files = ["relative/path1", "relative/two", "more/relative"]

    check_patterns(files, PathPrefixPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("/*", None),
    ("/./*", None),
    ("*", None),
    ("*/*", None),
    ("*///*", None),
    ("/home/u", []),
    ("/home/*",
     ["/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile", "/home/user2/public_html/index.html",
      "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ("/home/user/*", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("*/.pr????e", ["/home/user/.profile", "/home/user2/.profile"]),
    ("///etc//////*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2/*", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv*", ["/srv/messages", "/srv/dmesg"]),
    ("/home/*/.thumbnails", ["/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ])
def test_patterns_fnmatch(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv/messages", "/srv/dmesg",
        "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    check_patterns(files, FnmatchPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("*", None),
    ("**/*", None),
    ("/**/*", None),
    ("/./*", None),
    ("*/*", None),
    ("*///*", None),
    ("/home/u", []),
    ("/home/*",
     ["/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile", "/home/user2/public_html/index.html",
      "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ("/home/user/*", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc/*/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/etc/**/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/etc/**/*/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("*/.pr????e", []),
    ("**/.pr????e", ["/home/user/.profile", "/home/user2/.profile"]),
    ("///etc//////*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2/", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/./home//..//home/user2/**/*", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv*/", ["/srv/messages", "/srv/dmesg", "/srv2/blafasel"]),
    ("/srv*", ["/srv", "/srv/messages", "/srv/dmesg", "/srv2", "/srv2/blafasel"]),
    ("/srv/*", ["/srv/messages", "/srv/dmesg"]),
    ("/srv2/**", ["/srv2", "/srv2/blafasel"]),
    ("/srv2/**/", ["/srv2/blafasel"]),
    ("/home/*/.thumbnails", ["/home/foo/.thumbnails"]),
    ("/home/*/*/.thumbnails", ["/home/foo/bar/.thumbnails"]),
    ])
def test_patterns_shell(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv", "/srv/messages", "/srv/dmesg",
        "/srv2", "/srv2/blafasel", "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    check_patterns(files, ShellPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("", None),
    (".*", None),
    ("^/", None),
    ("^abc$", []),
    ("^[^/]", []),
    ("^(?!/srv|/foo|/opt)",
     ["/home", "/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile",
      "/home/user2/public_html/index.html", "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails", ]),
    ])
def test_patterns_regex(pattern, expected):
    files = [
        '/srv/data', '/foo/bar', '/home',
        '/home/user/.profile', '/home/user/.bashrc',
        '/home/user2/.profile', '/home/user2/public_html/index.html',
        '/opt/log/messages.txt', '/opt/log/dmesg.txt',
        "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    obj = RegexPattern(pattern)
    assert str(obj) == pattern
    assert obj.pattern == pattern

    check_patterns(files, obj, expected)


def test_regex_pattern():
    # The forward slash must match the platform-specific path separator
    assert RegexPattern("^/$").match("/")
    assert RegexPattern("^/$").match(os.path.sep)
    assert not RegexPattern(r"^\\$").match("/")


def use_normalized_unicode():
    return sys.platform in ("darwin",)


def _make_test_patterns(pattern):
    return [PathPrefixPattern(pattern),
            FnmatchPattern(pattern),
            RegexPattern("^{}/foo$".format(pattern)),
            ShellPattern(pattern),
            ]


@pytest.mark.parametrize("pattern", _make_test_patterns("b\N{LATIN SMALL LETTER A WITH ACUTE}"))
def test_composed_unicode_pattern(pattern):
    assert pattern.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
    assert pattern.match("ba\N{COMBINING ACUTE ACCENT}/foo") == use_normalized_unicode()


@pytest.mark.parametrize("pattern", _make_test_patterns("ba\N{COMBINING ACUTE ACCENT}"))
def test_decomposed_unicode_pattern(pattern):
    assert pattern.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo") == use_normalized_unicode()
    assert pattern.match("ba\N{COMBINING ACUTE ACCENT}/foo")


@pytest.mark.parametrize("pattern", _make_test_patterns(str(b"ba\x80", "latin1")))
def test_invalid_unicode_pattern(pattern):
    assert not pattern.match("ba/foo")
    assert pattern.match(str(b"ba\x80/foo", "latin1"))


@pytest.mark.parametrize("lines, expected", [
    # "None" means all files, i.e. none excluded
    ([], None),
    (["# Comment only"], None),
    (["*"], []),
    (["# Comment",
      "*/something00.txt",
      "  *whitespace*  ",
      # Whitespace before comment
      " #/ws*",
      # Empty line
      "",
      "# EOF"],
     ["/more/data", "/home", " #/wsfoobar"]),
    (["re:.*"], []),
    (["re:\s"], ["/data/something00.txt", "/more/data", "/home"]),
    ([r"re:(.)(\1)"], ["/more/data", "/home", "\tstart/whitespace", "/whitespace/end\t"]),
    (["", "", "",
      "# This is a test with mixed pattern styles",
      # Case-insensitive pattern
      "re:(?i)BAR|ME$",
      "",
      "*whitespace*",
      "fm:*/something00*"],
     ["/more/data"]),
    ([r"  re:^\s  "], ["/data/something00.txt", "/more/data", "/home", "/whitespace/end\t"]),
    ([r"  re:\s$  "], ["/data/something00.txt", "/more/data", "/home", " #/wsfoobar", "\tstart/whitespace"]),
    (["pp:./"], None),
    (["pp:/"], [" #/wsfoobar", "\tstart/whitespace"]),
    (["pp:aaabbb"], None),
    (["pp:/data", "pp: #/", "pp:\tstart", "pp:/whitespace"], ["/more/data", "/home"]),
    ])
def test_patterns_from_file(tmpdir, lines, expected):
    files = [
        '/data/something00.txt', '/more/data', '/home',
        ' #/wsfoobar',
        '\tstart/whitespace',
        '/whitespace/end\t',
    ]

    def evaluate(filename):
        matcher = PatternMatcher(fallback=True)
        matcher.add(load_excludes(open(filename, "rt")), False)
        return [path for path in files if matcher.match(path)]

    exclfile = tmpdir.join("exclude.txt")

    with exclfile.open("wt") as fh:
        fh.write("\n".join(lines))

    assert evaluate(str(exclfile)) == (files if expected is None else expected)


@pytest.mark.parametrize("pattern, cls", [
    ("", FnmatchPattern),

    # Default style
    ("*", FnmatchPattern),
    ("/data/*", FnmatchPattern),

    # fnmatch style
    ("fm:", FnmatchPattern),
    ("fm:*", FnmatchPattern),
    ("fm:/data/*", FnmatchPattern),
    ("fm:fm:/data/*", FnmatchPattern),

    # Regular expression
    ("re:", RegexPattern),
    ("re:.*", RegexPattern),
    ("re:^/something/", RegexPattern),
    ("re:re:^/something/", RegexPattern),

    # Path prefix
    ("pp:", PathPrefixPattern),
    ("pp:/", PathPrefixPattern),
    ("pp:/data/", PathPrefixPattern),
    ("pp:pp:/data/", PathPrefixPattern),

    # Shell-pattern style
    ("sh:", ShellPattern),
    ("sh:*", ShellPattern),
    ("sh:/data/*", ShellPattern),
    ("sh:sh:/data/*", ShellPattern),
    ])
def test_parse_pattern(pattern, cls):
    assert isinstance(parse_pattern(pattern), cls)


@pytest.mark.parametrize("pattern", ["aa:", "fo:*", "00:", "x1:abc"])
def test_parse_pattern_error(pattern):
    with pytest.raises(ValueError):
        parse_pattern(pattern)


def test_pattern_matcher():
    pm = PatternMatcher()

    assert pm.fallback is None

    for i in ["", "foo", "bar"]:
        assert pm.match(i) is None

    pm.add([RegexPattern("^a")], "A")
    pm.add([RegexPattern("^b"), RegexPattern("^z")], "B")
    pm.add([RegexPattern("^$")], "Empty")
    pm.fallback = "FileNotFound"

    assert pm.match("") == "Empty"
    assert pm.match("aaa") == "A"
    assert pm.match("bbb") == "B"
    assert pm.match("ccc") == "FileNotFound"
    assert pm.match("xyz") == "FileNotFound"
    assert pm.match("z") == "B"

    assert PatternMatcher(fallback="hey!").fallback == "hey!"


def test_compression_specs():
    with pytest.raises(ValueError):
        CompressionSpec('')
    assert CompressionSpec('none') == dict(name='none')
    assert CompressionSpec('lz4') == dict(name='lz4')
    assert CompressionSpec('zlib') == dict(name='zlib', level=6)
    assert CompressionSpec('zlib,0') == dict(name='zlib', level=0)
    assert CompressionSpec('zlib,9') == dict(name='zlib', level=9)
    with pytest.raises(ValueError):
        CompressionSpec('zlib,9,invalid')
    assert CompressionSpec('lzma') == dict(name='lzma', level=6)
    assert CompressionSpec('lzma,0') == dict(name='lzma', level=0)
    assert CompressionSpec('lzma,9') == dict(name='lzma', level=9)
    with pytest.raises(ValueError):
        CompressionSpec('lzma,9,invalid')
    with pytest.raises(ValueError):
        CompressionSpec('invalid')


def test_chunkerparams():
    assert ChunkerParams('19,23,21,4095') == (19, 23, 21, 4095)
    assert ChunkerParams('10,23,16,4095') == (10, 23, 16, 4095)
    with pytest.raises(ValueError):
        ChunkerParams('19,24,21,4095')


class MakePathSafeTestCase(BaseTestCase):

    def test(self):
        self.assert_equal(make_path_safe('/foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/f/bar'), 'f/bar')
        self.assert_equal(make_path_safe('fo/bar'), 'fo/bar')
        self.assert_equal(make_path_safe('../foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('../../foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/'), '.')
        self.assert_equal(make_path_safe('/'), '.')


class MockArchive:

    def __init__(self, ts):
        self.ts = ts

    def __repr__(self):
        return repr(self.ts)


class PruneSplitTestCase(BaseTestCase):

    def test(self):

        def local_to_UTC(month, day):
            """Convert noon on the month and day in 2013 to UTC."""
            seconds = mktime(strptime('2013-%02d-%02d 12:00' % (month, day), '%Y-%m-%d %H:%M'))
            return datetime.fromtimestamp(seconds, tz=timezone.utc)

        def subset(lst, indices):
            return {lst[i] for i in indices}

        def dotest(test_archives, n, skip, indices):
            for ta in test_archives, reversed(test_archives):
                self.assert_equal(set(prune_split(ta, '%Y-%m', n, skip)),
                                  subset(test_archives, indices))

        test_pairs = [(1, 1), (2, 1), (2, 28), (3, 1), (3, 2), (3, 31), (5, 1)]
        test_dates = [local_to_UTC(month, day) for month, day in test_pairs]
        test_archives = [MockArchive(date) for date in test_dates]

        dotest(test_archives, 3, [], [6, 5, 2])
        dotest(test_archives, -1, [], [6, 5, 2, 0])
        dotest(test_archives, 3, [test_archives[6]], [5, 2, 0])
        dotest(test_archives, 3, [test_archives[5]], [6, 2, 0])
        dotest(test_archives, 3, [test_archives[4]], [6, 5, 2])
        dotest(test_archives, 0, [], [])


class PruneWithinTestCase(BaseTestCase):

    def test(self):

        def subset(lst, indices):
            return {lst[i] for i in indices}

        def dotest(test_archives, within, indices):
            for ta in test_archives, reversed(test_archives):
                self.assert_equal(set(prune_within(ta, within)),
                                  subset(test_archives, indices))

        # 1 minute, 1.5 hours, 2.5 hours, 3.5 hours, 25 hours, 49 hours
        test_offsets = [60, 90*60, 150*60, 210*60, 25*60*60, 49*60*60]
        now = datetime.now(timezone.utc)
        test_dates = [now - timedelta(seconds=s) for s in test_offsets]
        test_archives = [MockArchive(date) for date in test_dates]

        dotest(test_archives, '1H', [0])
        dotest(test_archives, '2H', [0, 1])
        dotest(test_archives, '3H', [0, 1, 2])
        dotest(test_archives, '24H', [0, 1, 2, 3])
        dotest(test_archives, '26H', [0, 1, 2, 3, 4])
        dotest(test_archives, '2d', [0, 1, 2, 3, 4])
        dotest(test_archives, '50H', [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '3d', [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1w', [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1m', [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1y', [0, 1, 2, 3, 4, 5])


class StableDictTestCase(BaseTestCase):

    def test(self):
        d = StableDict(foo=1, bar=2, boo=3, baz=4)
        self.assert_equal(list(d.items()), [('bar', 2), ('baz', 4), ('boo', 3), ('foo', 1)])
        self.assert_equal(hashlib.md5(msgpack.packb(d)).hexdigest(), 'fc78df42cd60691b3ac3dd2a2b39903f')


class TestParseTimestamp(BaseTestCase):

    def test(self):
        self.assert_equal(parse_timestamp('2015-04-19T20:25:00.226410'), datetime(2015, 4, 19, 20, 25, 0, 226410, timezone.utc))
        self.assert_equal(parse_timestamp('2015-04-19T20:25:00'), datetime(2015, 4, 19, 20, 25, 0, 0, timezone.utc))


def test_get_cache_dir():
    """test that get_cache_dir respects environment"""
    # reset BORG_CACHE_DIR in order to test default
    old_env = None
    if os.environ.get('BORG_CACHE_DIR'):
        old_env = os.environ['BORG_CACHE_DIR']
        del(os.environ['BORG_CACHE_DIR'])
    assert get_cache_dir() == os.path.join(os.path.expanduser('~'), '.cache', 'borg')
    os.environ['XDG_CACHE_HOME'] = '/var/tmp/.cache'
    assert get_cache_dir() == os.path.join('/var/tmp/.cache', 'borg')
    os.environ['BORG_CACHE_DIR'] = '/var/tmp'
    assert get_cache_dir() == '/var/tmp'
    # reset old env
    if old_env is not None:
        os.environ['BORG_CACHE_DIR'] = old_env


def test_get_keys_dir():
    """test that get_keys_dir respects environment"""
    # reset BORG_KEYS_DIR in order to test default
    old_env = None
    if os.environ.get('BORG_KEYS_DIR'):
        old_env = os.environ['BORG_KEYS_DIR']
        del(os.environ['BORG_KEYS_DIR'])
    assert get_keys_dir() == os.path.join(os.path.expanduser('~'), '.config', 'borg', 'keys')
    os.environ['XDG_CONFIG_HOME'] = '/var/tmp/.config'
    assert get_keys_dir() == os.path.join('/var/tmp/.config', 'borg', 'keys')
    os.environ['BORG_KEYS_DIR'] = '/var/tmp'
    assert get_keys_dir() == '/var/tmp'
    # reset old env
    if old_env is not None:
        os.environ['BORG_KEYS_DIR'] = old_env


@pytest.fixture()
def stats():
    stats = Statistics()
    stats.update(20, 10, unique=True)
    return stats


def test_stats_basic(stats):
    assert stats.osize == 20
    assert stats.csize == stats.usize == 10
    stats.update(20, 10, unique=False)
    assert stats.osize == 40
    assert stats.csize == 20
    assert stats.usize == 10


def tests_stats_progress(stats, columns=80):
    os.environ['COLUMNS'] = str(columns)
    out = StringIO()
    stats.show_progress(stream=out)
    s = '20 B O 10 B C 10 B D 0 N '
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = StringIO()
    stats.update(10**3, 0, unique=False)
    stats.show_progress(item={b'path': 'foo'}, final=False, stream=out)
    s = '1.02 kB O 10 B C 10 B D 0 N foo'
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"
    out = StringIO()
    stats.show_progress(item={b'path': 'foo'*40}, final=False, stream=out)
    s = '1.02 kB O 10 B C 10 B D 0 N foofoofoofoofoofoofoofo...oofoofoofoofoofoofoofoofoo'
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


def test_stats_format(stats):
    assert str(stats) == """\
                       Original size      Compressed size    Deduplicated size
This archive:                   20 B                 10 B                 10 B"""
    s = "{0.osize_fmt}".format(stats)
    assert s == "20 B"
    # kind of redundant, but id is variable so we can't match reliably
    assert repr(stats) == '<Statistics object at {:#x} (20, 10, 10)>'.format(id(stats))


def test_file_size():
    """test the size formatting routines"""
    si_size_map = {
        0: '0 B',  # no rounding necessary for those
        1: '1 B',
        142: '142 B',
        999: '999 B',
        1000: '1.00 kB',  # rounding starts here
        1001: '1.00 kB',  # should be rounded away
        1234: '1.23 kB',  # should be rounded down
        1235: '1.24 kB',  # should be rounded up
        1010: '1.01 kB',  # rounded down as well
        999990000: '999.99 MB',  # rounded down
        999990001: '999.99 MB',  # rounded down
        999995000: '1.00 GB',  # rounded up to next unit
        10**6: '1.00 MB',  # and all the remaining units, megabytes
        10**9: '1.00 GB',  # gigabytes
        10**12: '1.00 TB',  # terabytes
        10**15: '1.00 PB',  # petabytes
        10**18: '1.00 EB',  # exabytes
        10**21: '1.00 ZB',  # zottabytes
        10**24: '1.00 YB',  # yottabytes
    }
    for size, fmt in si_size_map.items():
        assert format_file_size(size) == fmt


def test_file_size_precision():
    assert format_file_size(1234, precision=1) == '1.2 kB'  # rounded down
    assert format_file_size(1254, precision=1) == '1.3 kB'  # rounded up
    assert format_file_size(999990000, precision=1) == '1.0 GB'  # and not 999.9 MB or 1000.0 MB


def test_is_slow_msgpack():
    saved_packer = msgpack.Packer
    try:
        msgpack.Packer = msgpack.fallback.Packer
        assert is_slow_msgpack()
    finally:
        msgpack.Packer = saved_packer
    # this assumes that we have fast msgpack on test platform:
    assert not is_slow_msgpack()


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
    input = FakeInputs(['YES', 'SURE', 'NOPE', ])
    assert yes(truish=('YES', ), input=input)
    assert yes(truish=('SURE', ), input=input)
    assert not yes(falsish=('NOPE', ), input=input)


def test_yes_env():
    for value in TRUISH:
        with environment_variable(OVERRIDE_THIS=value):
            assert yes(env_var_override='OVERRIDE_THIS')
    for value in FALSISH:
        with environment_variable(OVERRIDE_THIS=value):
            assert not yes(env_var_override='OVERRIDE_THIS')


def test_yes_env_default():
    for value in DEFAULTISH:
        with environment_variable(OVERRIDE_THIS=value):
            assert yes(env_var_override='OVERRIDE_THIS', default=True)
        with environment_variable(OVERRIDE_THIS=value):
            assert not yes(env_var_override='OVERRIDE_THIS', default=False)


def test_yes_defaults():
    input = FakeInputs(['invalid', '', ' '])
    assert not yes(input=input)  # default=False
    assert not yes(input=input)
    assert not yes(input=input)
    input = FakeInputs(['invalid', '', ' '])
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    input = FakeInputs([])
    assert yes(default=True, input=input)
    assert not yes(default=False, input=input)
    with pytest.raises(ValueError):
        yes(default=None)


def test_yes_retry():
    input = FakeInputs(['foo', 'bar', TRUISH[0], ])
    assert yes(retry_msg='Retry: ', input=input)
    input = FakeInputs(['foo', 'bar', FALSISH[0], ])
    assert not yes(retry_msg='Retry: ', input=input)


def test_yes_no_retry():
    input = FakeInputs(['foo', 'bar', TRUISH[0], ])
    assert not yes(retry=False, default=False, input=input)
    input = FakeInputs(['foo', 'bar', FALSISH[0], ])
    assert yes(retry=False, default=True, input=input)


def test_yes_output(capfd):
    input = FakeInputs(['invalid', 'y', 'n'])
    assert yes(msg='intro-msg', false_msg='false-msg', true_msg='true-msg', retry_msg='retry-msg', input=input)
    out, err = capfd.readouterr()
    assert out == ''
    assert 'intro-msg' in err
    assert 'retry-msg' in err
    assert 'true-msg' in err
    assert not yes(msg='intro-msg', false_msg='false-msg', true_msg='true-msg', retry_msg='retry-msg', input=input)
    out, err = capfd.readouterr()
    assert out == ''
    assert 'intro-msg' in err
    assert 'retry-msg' not in err
    assert 'false-msg' in err


def test_progress_percentage_multiline(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, same_line=False, msg="%3.0f%%", file=sys.stderr)
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == '  0%\n'
    pi.show(420)
    out, err = capfd.readouterr()
    assert err == ' 42%\n'
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == '100%\n'
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ''


def test_progress_percentage_sameline(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, same_line=True, msg="%3.0f%%", file=sys.stderr)
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == '  0%\r'
    pi.show(420)
    out, err = capfd.readouterr()
    assert err == ' 42%\r'
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == '100%\r'
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ' ' * 4 + '\r'


def test_progress_percentage_step(capfd):
    pi = ProgressIndicatorPercent(100, step=2, start=0, same_line=False, msg="%3.0f%%", file=sys.stderr)
    pi.show()
    out, err = capfd.readouterr()
    assert err == '  0%\n'
    pi.show()
    out, err = capfd.readouterr()
    assert err == ''  # no output at 1% as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == '  2%\n'


def test_progress_endless(capfd):
    pi = ProgressIndicatorEndless(step=1, file=sys.stderr)
    pi.show()
    out, err = capfd.readouterr()
    assert err == '.'
    pi.show()
    out, err = capfd.readouterr()
    assert err == '.'
    pi.finish()
    out, err = capfd.readouterr()
    assert err == '\n'


def test_progress_endless_step(capfd):
    pi = ProgressIndicatorEndless(step=2, file=sys.stderr)
    pi.show()
    out, err = capfd.readouterr()
    assert err == ''  # no output here as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == '.'
    pi.show()
    out, err = capfd.readouterr()
    assert err == ''  # no output here as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == '.'
