import hashlib
from time import mktime, strptime
from datetime import datetime, timezone, timedelta
from io import StringIO
import os

import pytest
import sys
import msgpack
import msgpack.fallback

from ..helpers import adjust_patterns, exclude_path, Location, format_file_size, format_timedelta, IncludePattern, ExcludePattern, make_path_safe, \
    prune_within, prune_split, get_cache_dir, Statistics, is_slow_msgpack, yes, \
    StableDict, int_to_bigint, bigint_to_int, parse_timestamp, CompressionSpec, ChunkerParams, \
    ProgressIndicatorPercent, ProgressIndicatorEndless
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


class PatternTestCase(BaseTestCase):

    files = [
        '/etc/passwd', '/etc/hosts', '/home',
        '/home/user/.profile', '/home/user/.bashrc',
        '/home/user2/.profile', '/home/user2/public_html/index.html',
        '/var/log/messages', '/var/log/dmesg',
    ]

    def evaluate(self, paths, excludes):
        patterns = adjust_patterns(paths, [ExcludePattern(p) for p in excludes])
        return [path for path in self.files if not exclude_path(path, patterns)]

    def test(self):
        self.assert_equal(self.evaluate(['/'], []), self.files)
        self.assert_equal(self.evaluate([], []), self.files)
        self.assert_equal(self.evaluate(['/'], ['/h']), self.files)
        self.assert_equal(self.evaluate(['/'], ['/home']),
                          ['/etc/passwd', '/etc/hosts', '/var/log/messages', '/var/log/dmesg'])
        self.assert_equal(self.evaluate(['/'], ['/home/']),
                          ['/etc/passwd', '/etc/hosts', '/home', '/var/log/messages', '/var/log/dmesg'])
        self.assert_equal(self.evaluate(['/home/u'], []), [])
        self.assert_equal(self.evaluate(['/', '/home', '/etc/hosts'], ['/']), [])
        self.assert_equal(self.evaluate(['/home/'], ['/home/user2']),
                          ['/home', '/home/user/.profile', '/home/user/.bashrc'])
        self.assert_equal(self.evaluate(['/'], ['*.profile', '/var/log']),
                          ['/etc/passwd', '/etc/hosts', '/home', '/home/user/.bashrc', '/home/user2/public_html/index.html'])
        self.assert_equal(self.evaluate(['/'], ['/home/*/public_html', '*.profile', '*/log/*']),
                          ['/etc/passwd', '/etc/hosts', '/home', '/home/user/.bashrc'])
        self.assert_equal(self.evaluate(['/etc/', '/var'], ['dmesg']),
                          ['/etc/passwd', '/etc/hosts', '/var/log/messages', '/var/log/dmesg'])


@pytest.mark.skipif(sys.platform in ('darwin',), reason='all but OS X test')
class PatternNonAsciiTestCase(BaseTestCase):
    def testComposedUnicode(self):
        pattern = 'b\N{LATIN SMALL LETTER A WITH ACUTE}'
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert i.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert not i.match("ba\N{COMBINING ACUTE ACCENT}/foo")
        assert e.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert not e.match("ba\N{COMBINING ACUTE ACCENT}/foo")

    def testDecomposedUnicode(self):
        pattern = 'ba\N{COMBINING ACUTE ACCENT}'
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert not i.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert i.match("ba\N{COMBINING ACUTE ACCENT}/foo")
        assert not e.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert e.match("ba\N{COMBINING ACUTE ACCENT}/foo")

    def testInvalidUnicode(self):
        pattern = str(b'ba\x80', 'latin1')
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert not i.match("ba/foo")
        assert i.match(str(b"ba\x80/foo", 'latin1'))
        assert not e.match("ba/foo")
        assert e.match(str(b"ba\x80/foo", 'latin1'))


@pytest.mark.skipif(sys.platform not in ('darwin',), reason='OS X test')
class OSXPatternNormalizationTestCase(BaseTestCase):
    def testComposedUnicode(self):
        pattern = 'b\N{LATIN SMALL LETTER A WITH ACUTE}'
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert i.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert i.match("ba\N{COMBINING ACUTE ACCENT}/foo")
        assert e.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert e.match("ba\N{COMBINING ACUTE ACCENT}/foo")

    def testDecomposedUnicode(self):
        pattern = 'ba\N{COMBINING ACUTE ACCENT}'
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert i.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert i.match("ba\N{COMBINING ACUTE ACCENT}/foo")
        assert e.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
        assert e.match("ba\N{COMBINING ACUTE ACCENT}/foo")

    def testInvalidUnicode(self):
        pattern = str(b'ba\x80', 'latin1')
        i = IncludePattern(pattern)
        e = ExcludePattern(pattern)

        assert not i.match("ba/foo")
        assert i.match(str(b"ba\x80/foo", 'latin1'))
        assert not e.match("ba/foo")
        assert e.match(str(b"ba\x80/foo", 'latin1'))


def test_compression_specs():
    with pytest.raises(ValueError):
        CompressionSpec('')
    assert CompressionSpec('0') == dict(name='zlib', level=0)
    assert CompressionSpec('1') == dict(name='zlib', level=1)
    assert CompressionSpec('9') == dict(name='zlib', level=9)
    with pytest.raises(ValueError):
        CompressionSpec('10')
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
    """test that get_cache_dir respects environement"""
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


def test_yes_simple():
    input = FakeInputs(['y', 'Y', 'yes', 'Yes', ])
    assert yes(input=input)
    assert yes(input=input)
    assert yes(input=input)
    assert yes(input=input)
    input = FakeInputs(['n', 'N', 'no', 'No', ])
    assert not yes(input=input)
    assert not yes(input=input)
    assert not yes(input=input)
    assert not yes(input=input)


def test_yes_custom():
    input = FakeInputs(['YES', 'SURE', 'NOPE', ])
    assert yes(truish=('YES', ), input=input)
    assert yes(truish=('SURE', ), input=input)
    assert not yes(falsish=('NOPE', ), input=input)


def test_yes_env():
    input = FakeInputs(['n', 'n'])
    with environment_variable(OVERRIDE_THIS='nonempty'):
        assert yes(env_var_override='OVERRIDE_THIS', input=input)
    with environment_variable(OVERRIDE_THIS=None):  # env not set
        assert not yes(env_var_override='OVERRIDE_THIS', input=input)


def test_yes_defaults():
    input = FakeInputs(['invalid', '', ' '])
    assert not yes(input=input)  # default=False
    assert not yes(input=input)
    assert not yes(input=input)
    input = FakeInputs(['invalid', '', ' '])
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    assert yes(default=True, input=input)
    ifile = StringIO()
    assert yes(default_notty=True, ifile=ifile)
    assert not yes(default_notty=False, ifile=ifile)
    input = FakeInputs([])
    assert yes(default_eof=True, input=input)
    assert not yes(default_eof=False, input=input)
    with pytest.raises(ValueError):
        yes(default=None)
    with pytest.raises(ValueError):
        yes(default_notty='invalid')
    with pytest.raises(ValueError):
        yes(default_eof='invalid')


def test_yes_retry():
    input = FakeInputs(['foo', 'bar', 'y', ])
    assert yes(retry_msg='Retry: ', input=input)
    input = FakeInputs(['foo', 'bar', 'N', ])
    assert not yes(retry_msg='Retry: ', input=input)


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
