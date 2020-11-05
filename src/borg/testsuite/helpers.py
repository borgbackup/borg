import hashlib
import io
import os
import shutil
import sys
from argparse import ArgumentTypeError
from datetime import datetime, timezone, timedelta
from time import mktime, strptime, sleep

import pytest

from .. import platform
from ..helpers import Location
from ..helpers import Buffer
from ..helpers import partial_format, format_file_size, parse_file_size, format_timedelta, format_line, PlaceholderError, replace_placeholders
from ..helpers import make_path_safe, clean_lines
from ..helpers import interval, prune_within, prune_split
from ..helpers import get_base_dir, get_cache_dir, get_keys_dir, get_security_dir, get_config_dir
from ..helpers import is_slow_msgpack
from ..helpers import msgpack, msgpack_fallback
from ..helpers import yes, TRUISH, FALSISH, DEFAULTISH
from ..helpers import StableDict, int_to_bigint, bigint_to_int, bin_to_hex
from ..helpers import parse_timestamp, ChunkIteratorFileWrapper, ChunkerParams
from ..helpers import ProgressIndicatorPercent, ProgressIndicatorEndless
from ..helpers import swidth_slice
from ..helpers import chunkit
from ..helpers import safe_ns, safe_s, SUPPORT_32BIT_PLATFORMS
from ..helpers import popen_with_error_handling
from ..helpers import dash_open

from . import BaseTestCase, FakeInputs


class BigIntTestCase(BaseTestCase):

    def test_bigint(self):
        self.assert_equal(int_to_bigint(0), 0)
        self.assert_equal(int_to_bigint(2**63-1), 2**63-1)
        self.assert_equal(int_to_bigint(-2**63+1), -2**63+1)
        self.assert_equal(int_to_bigint(2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\x00')
        self.assert_equal(int_to_bigint(-2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\xff')
        self.assert_equal(bigint_to_int(int_to_bigint(-2**70)), -2**70)
        self.assert_equal(bigint_to_int(int_to_bigint(2**70)), 2**70)


def test_bin_to_hex():
    assert bin_to_hex(b'') == ''
    assert bin_to_hex(b'\x00\x01\xff') == '0001ff'


class TestLocationWithoutEnv:
    @pytest.fixture
    def keys_dir(self, tmpdir, monkeypatch):
        tmpdir = str(tmpdir)
        monkeypatch.setenv('BORG_KEYS_DIR', tmpdir)
        if not tmpdir.endswith(os.path.sep):
            tmpdir += os.path.sep
        return tmpdir

    def test_ssh(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('ssh://user@host:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')"
        assert Location('ssh://user@host:1234/some/path::archive').to_key_filename() == keys_dir + 'host__some_path'
        assert repr(Location('ssh://user@host:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@host/some/path')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[::]:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='::', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('ssh://user@[::]:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='::', port=1234, path='/some/path', archive=None)"
        assert Location('ssh://user@[::]:1234/some/path').to_key_filename() == keys_dir + '____some_path'
        assert repr(Location('ssh://user@[::]/some/path')) == \
            "Location(proto='ssh', user='user', host='::', port=None, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[2001:db8::]:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('ssh://user@[2001:db8::]:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::', port=1234, path='/some/path', archive=None)"
        assert Location('ssh://user@[2001:db8::]:1234/some/path').to_key_filename() == keys_dir + '2001_db8____some_path'
        assert repr(Location('ssh://user@[2001:db8::]/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::', port=None, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[2001:db8::c0:ffee]:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('ssh://user@[2001:db8::c0:ffee]:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=1234, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[2001:db8::c0:ffee]/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=None, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[2001:db8::192.0.2.1]:1234/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('ssh://user@[2001:db8::192.0.2.1]:1234/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=1234, path='/some/path', archive=None)"
        assert repr(Location('ssh://user@[2001:db8::192.0.2.1]/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=None, path='/some/path', archive=None)"
        assert Location('ssh://user@[2001:db8::192.0.2.1]/some/path').to_key_filename() == keys_dir + '2001_db8__192_0_2_1__some_path'

    def test_file(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('file:///some/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')"
        assert repr(Location('file:///some/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive=None)"
        assert Location('file:///some/path').to_key_filename() == keys_dir + 'some_path'

    def test_scp(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('user@host:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@host:/some/path')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"
        assert repr(Location('user@[::]:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='::', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@[::]:/some/path')) == \
            "Location(proto='ssh', user='user', host='::', port=None, path='/some/path', archive=None)"
        assert repr(Location('user@[2001:db8::]:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@[2001:db8::]:/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::', port=None, path='/some/path', archive=None)"
        assert repr(Location('user@[2001:db8::c0:ffee]:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@[2001:db8::c0:ffee]:/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::c0:ffee', port=None, path='/some/path', archive=None)"
        assert repr(Location('user@[2001:db8::192.0.2.1]:/some/path::archive')) == \
            "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=None, path='/some/path', archive='archive')"
        assert repr(Location('user@[2001:db8::192.0.2.1]:/some/path')) == \
            "Location(proto='ssh', user='user', host='2001:db8::192.0.2.1', port=None, path='/some/path', archive=None)"
        assert Location('user@[2001:db8::192.0.2.1]:/some/path').to_key_filename() == keys_dir + '2001_db8__192_0_2_1__some_path'

    def test_smb(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('file:////server/share/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='//server/share/path', archive='archive')"
        assert Location('file:////server/share/path::archive').to_key_filename() == keys_dir + 'server_share_path'

    def test_folder(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive='archive')"
        assert repr(Location('path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive=None)"
        assert Location('path').to_key_filename() == keys_dir + 'path'

    def test_long_path(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert Location(os.path.join(*(40 * ['path']))).to_key_filename() == keys_dir + '_'.join(20 * ['path']) + '_'

    def test_abspath(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('/some/absolute/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        assert repr(Location('/some/absolute/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive=None)"
        assert Location('/some/absolute/path').to_key_filename() == keys_dir + 'some_absolute_path'
        assert repr(Location('ssh://user@host/some/path')) == \
               "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"
        assert Location('ssh://user@host/some/path').to_key_filename() == keys_dir + 'host__some_path'

    def test_relpath(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('some/relative/path::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        assert repr(Location('some/relative/path')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive=None)"
        assert Location('some/relative/path').to_key_filename() == keys_dir + 'some_relative_path'
        assert repr(Location('ssh://user@host/./some/path')) == \
               "Location(proto='ssh', user='user', host='host', port=None, path='/./some/path', archive=None)"
        assert Location('ssh://user@host/./some/path').to_key_filename() == keys_dir + 'host__some_path'
        assert repr(Location('ssh://user@host/~/some/path')) == \
               "Location(proto='ssh', user='user', host='host', port=None, path='/~/some/path', archive=None)"
        assert Location('ssh://user@host/~/some/path').to_key_filename() == keys_dir + 'host__some_path'
        assert repr(Location('ssh://user@host/~user/some/path')) == \
               "Location(proto='ssh', user='user', host='host', port=None, path='/~user/some/path', archive=None)"
        assert Location('ssh://user@host/~user/some/path').to_key_filename() == keys_dir + 'host__user_some_path'

    def test_with_colons(self, monkeypatch, keys_dir):
        monkeypatch.delenv('BORG_REPO', raising=False)
        assert repr(Location('/abs/path:w:cols::arch:col')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols', archive='arch:col')"
        assert repr(Location('/abs/path:with:colons::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/abs/path:with:colons', archive='archive')"
        assert repr(Location('/abs/path:with:colons')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/abs/path:with:colons', archive=None)"
        assert Location('/abs/path:with:colons').to_key_filename() == keys_dir + 'abs_path_with_colons'

    def test_user_parsing(self):
        # see issue #1930
        assert repr(Location('host:path::2016-12-31@23:59:59')) == \
            "Location(proto='ssh', user=None, host='host', port=None, path='path', archive='2016-12-31@23:59:59')"
        assert repr(Location('ssh://host/path::2016-12-31@23:59:59')) == \
            "Location(proto='ssh', user=None, host='host', port=None, path='/path', archive='2016-12-31@23:59:59')"

    def test_with_timestamp(self):
        assert repr(Location('path::archive-{utcnow}').with_timestamp(datetime(2002, 9, 19, tzinfo=timezone.utc))) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive='archive-2002-09-19T00:00:00')"

    def test_underspecified(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        with pytest.raises(ValueError):
            Location('::archive')
        with pytest.raises(ValueError):
            Location('::')
        with pytest.raises(ValueError):
            Location()

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
                Location(Location(location).canonical_path()).canonical_path(), "failed: %s" % location

    def test_format_path(self, monkeypatch):
        monkeypatch.delenv('BORG_REPO', raising=False)
        test_pid = os.getpid()
        assert repr(Location('/some/path::archive{pid}')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive{}')".format(test_pid)
        location_time1 = Location('/some/path::archive{now:%s}')
        sleep(1.1)
        location_time2 = Location('/some/path::archive{now:%s}')
        assert location_time1.archive != location_time2.archive

    def test_bad_syntax(self):
        with pytest.raises(ValueError):
            # this is invalid due to the 2nd colon, correct: 'ssh://user@host/path'
            Location('ssh://user@host:/path')


class TestLocationWithEnv:
    def test_ssh(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'ssh://user@host:1234/some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive=None)"

    def test_file(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'file:///some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive=None)"

    def test_scp(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'user@host:/some/path')
        assert repr(Location('::archive')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive=None)"

    def test_folder(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='file', user=None, host=None, port=None, path='path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='file', user=None, host=None, port=None, path='path', archive=None)"

    def test_abspath(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', '/some/absolute/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive=None)"

    def test_relpath(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', 'some/relative/path')
        assert repr(Location('::archive')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        assert repr(Location('::')) == \
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive=None)"
        assert repr(Location()) == \
               "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive=None)"

    def test_with_colons(self, monkeypatch):
        monkeypatch.setenv('BORG_REPO', '/abs/path:w:cols')
        assert repr(Location('::arch:col')) == \
            "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols', archive='arch:col')"
        assert repr(Location('::')) == \
               "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols', archive=None)"
        assert repr(Location()) == \
               "Location(proto='file', user=None, host=None, port=None, path='/abs/path:w:cols', archive=None)"

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


class IntervalTestCase(BaseTestCase):
    def test_interval(self):
        self.assert_equal(interval('1H'), 1)
        self.assert_equal(interval('1d'), 24)
        self.assert_equal(interval('1w'), 168)
        self.assert_equal(interval('1m'), 744)
        self.assert_equal(interval('1y'), 8760)

    def test_interval_time_unit(self):
        with pytest.raises(ArgumentTypeError) as exc:
            interval('H')
        self.assert_equal(
            exc.value.args,
            ('Unexpected interval number "": expected an integer greater than 0',))
        with pytest.raises(ArgumentTypeError) as exc:
            interval('-1d')
        self.assert_equal(
            exc.value.args,
            ('Unexpected interval number "-1": expected an integer greater than 0',))
        with pytest.raises(ArgumentTypeError) as exc:
            interval('food')
        self.assert_equal(
            exc.value.args,
            ('Unexpected interval number "foo": expected an integer greater than 0',))

    def test_interval_number(self):
        with pytest.raises(ArgumentTypeError) as exc:
            interval('5')
        self.assert_equal(
            exc.value.args,
            ("Unexpected interval time unit \"5\": expected one of ['H', 'd', 'w', 'm', 'y']",))


class PruneWithinTestCase(BaseTestCase):
    def test_prune_within(self):

        def subset(lst, indices):
            return {lst[i] for i in indices}

        def dotest(test_archives, within, indices):
            for ta in test_archives, reversed(test_archives):
                self.assert_equal(set(prune_within(ta, interval(within))),
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


def test_get_base_dir(monkeypatch):
    """test that get_base_dir respects environment"""
    monkeypatch.delenv('BORG_BASE_DIR', raising=False)
    monkeypatch.delenv('HOME', raising=False)
    monkeypatch.delenv('USER', raising=False)
    assert get_base_dir() == os.path.expanduser('~')
    monkeypatch.setenv('USER', 'root')
    assert get_base_dir() == os.path.expanduser('~root')
    monkeypatch.setenv('HOME', '/var/tmp/home')
    assert get_base_dir() == '/var/tmp/home'
    monkeypatch.setenv('BORG_BASE_DIR', '/var/tmp/base')
    assert get_base_dir() == '/var/tmp/base'


def test_get_config_dir(monkeypatch):
    """test that get_config_dir respects environment"""
    monkeypatch.delenv('BORG_CONFIG_DIR', raising=False)
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
    assert get_config_dir() == os.path.join(os.path.expanduser('~'), '.config', 'borg')
    monkeypatch.setenv('XDG_CONFIG_HOME', '/var/tmp/.config')
    assert get_config_dir() == os.path.join('/var/tmp/.config', 'borg')
    monkeypatch.setenv('BORG_CONFIG_DIR', '/var/tmp')
    assert get_config_dir() == '/var/tmp'


def test_get_cache_dir(monkeypatch):
    """test that get_cache_dir respects environment"""
    monkeypatch.delenv('BORG_CACHE_DIR', raising=False)
    monkeypatch.delenv('XDG_CACHE_HOME', raising=False)
    assert get_cache_dir() == os.path.join(os.path.expanduser('~'), '.cache', 'borg')
    monkeypatch.setenv('XDG_CACHE_HOME', '/var/tmp/.cache')
    assert get_cache_dir() == os.path.join('/var/tmp/.cache', 'borg')
    monkeypatch.setenv('BORG_CACHE_DIR', '/var/tmp')
    assert get_cache_dir() == '/var/tmp'


def test_get_keys_dir(monkeypatch):
    """test that get_keys_dir respects environment"""
    monkeypatch.delenv('BORG_KEYS_DIR', raising=False)
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
    assert get_keys_dir() == os.path.join(os.path.expanduser('~'), '.config', 'borg', 'keys')
    monkeypatch.setenv('XDG_CONFIG_HOME', '/var/tmp/.config')
    assert get_keys_dir() == os.path.join('/var/tmp/.config', 'borg', 'keys')
    monkeypatch.setenv('BORG_KEYS_DIR', '/var/tmp')
    assert get_keys_dir() == '/var/tmp'


def test_get_security_dir(monkeypatch):
    """test that get_security_dir respects environment"""
    monkeypatch.delenv('BORG_SECURITY_DIR', raising=False)
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
    assert get_security_dir() == os.path.join(os.path.expanduser('~'), '.config', 'borg', 'security')
    assert get_security_dir(repository_id='1234') == os.path.join(os.path.expanduser('~'), '.config', 'borg', 'security', '1234')
    monkeypatch.setenv('XDG_CONFIG_HOME', '/var/tmp/.config')
    assert get_security_dir() == os.path.join('/var/tmp/.config', 'borg', 'security')
    monkeypatch.setenv('BORG_SECURITY_DIR', '/var/tmp')
    assert get_security_dir() == '/var/tmp'


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
        -1: '-1 B',  # negative value
        -1010: '-1.01 kB',  # negative value with rounding
    }
    for size, fmt in si_size_map.items():
        assert format_file_size(size) == fmt


def test_file_size_precision():
    assert format_file_size(1234, precision=1) == '1.2 kB'  # rounded down
    assert format_file_size(1254, precision=1) == '1.3 kB'  # rounded up
    assert format_file_size(999990000, precision=1) == '1.0 GB'  # and not 999.9 MB or 1000.0 MB


def test_file_size_sign():
    si_size_map = {
        0: '0 B',
        1: '+1 B',
        1234: '+1.23 kB',
        -1: '-1 B',
        -1234: '-1.23 kB',
    }
    for size, fmt in si_size_map.items():
        assert format_file_size(size, sign=True) == fmt


@pytest.mark.parametrize('string,value', (
    ('1', 1),
    ('20', 20),
    ('5K', 5000),
    ('1.75M', 1750000),
    ('1e+9', 1e9),
    ('-1T', -1e12),
))
def test_parse_file_size(string, value):
    assert parse_file_size(string) == int(value)


@pytest.mark.parametrize('string', (
    '', '5 Äpfel', '4E', '2229 bit', '1B',
))
def test_parse_file_size_invalid(string):
    with pytest.raises(ValueError):
        parse_file_size(string)


def test_is_slow_msgpack():
    saved_packer = msgpack.Packer
    try:
        msgpack.Packer = msgpack_fallback.Packer
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
    input = FakeInputs(['YES', 'SURE', 'NOPE', ])
    assert yes(truish=('YES', ), input=input)
    assert yes(truish=('SURE', ), input=input)
    assert not yes(falsish=('NOPE', ), input=input)


def test_yes_env(monkeypatch):
    for value in TRUISH:
        monkeypatch.setenv('OVERRIDE_THIS', value)
        assert yes(env_var_override='OVERRIDE_THIS')
    for value in FALSISH:
        monkeypatch.setenv('OVERRIDE_THIS', value)
        assert not yes(env_var_override='OVERRIDE_THIS')


def test_yes_env_default(monkeypatch):
    for value in DEFAULTISH:
        monkeypatch.setenv('OVERRIDE_THIS', value)
        assert yes(env_var_override='OVERRIDE_THIS', default=True)
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


def test_yes_env_output(capfd, monkeypatch):
    env_var = 'OVERRIDE_SOMETHING'
    monkeypatch.setenv(env_var, 'yes')
    assert yes(env_var_override=env_var)
    out, err = capfd.readouterr()
    assert out == ''
    assert env_var in err
    assert 'yes' in err


def test_progress_percentage_sameline(capfd, monkeypatch):
    # run the test as if it was in a 4x1 terminal
    monkeypatch.setenv('COLUMNS', '4')
    monkeypatch.setenv('LINES', '1')
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel('INFO')
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == '  0%\r'
    pi.show(420)
    pi.show(680)
    out, err = capfd.readouterr()
    assert err == ' 42%\r 68%\r'
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == '100%\r'
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ' ' * 4 + '\r'


def test_progress_percentage_step(capfd, monkeypatch):
    # run the test as if it was in a 4x1 terminal
    monkeypatch.setenv('COLUMNS', '4')
    monkeypatch.setenv('LINES', '1')
    pi = ProgressIndicatorPercent(100, step=2, start=0, msg="%3.0f%%")
    pi.logger.setLevel('INFO')
    pi.show()
    out, err = capfd.readouterr()
    assert err == '  0%\r'
    pi.show()
    out, err = capfd.readouterr()
    assert err == ''  # no output at 1% as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == '  2%\r'


def test_progress_percentage_quiet(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel('WARN')
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == ''
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == ''
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ''


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


def test_partial_format():
    assert partial_format('{space:10}', {'space': ' '}) == ' ' * 10
    assert partial_format('{foobar}', {'bar': 'wrong', 'foobar': 'correct'}) == 'correct'
    assert partial_format('{unknown_key}', {}) == '{unknown_key}'
    assert partial_format('{key}{{escaped_key}}', {}) == '{key}{{escaped_key}}'
    assert partial_format('{{escaped_key}}', {'escaped_key': 1234}) == '{{escaped_key}}'


def test_chunk_file_wrapper():
    cfw = ChunkIteratorFileWrapper(iter([b'abc', b'def']))
    assert cfw.read(2) == b'ab'
    assert cfw.read(50) == b'cdef'
    assert cfw.exhausted

    cfw = ChunkIteratorFileWrapper(iter([]))
    assert cfw.read(2) == b''
    assert cfw.exhausted


def test_chunkit():
    it = chunkit('abcdefg', 3)
    assert next(it) == ['a', 'b', 'c']
    assert next(it) == ['d', 'e', 'f']
    assert next(it) == ['g']
    with pytest.raises(StopIteration):
        next(it)
    with pytest.raises(StopIteration):
        next(it)

    it = chunkit('ab', 3)
    assert list(it) == [['a', 'b']]

    it = chunkit('', 3)
    assert list(it) == []


def test_clean_lines():
    conf = """\
#comment
data1 #data1
data2

 data3
""".splitlines(keepends=True)
    assert list(clean_lines(conf)) == ['data1 #data1', 'data2', 'data3', ]
    assert list(clean_lines(conf, lstrip=False)) == ['data1 #data1', 'data2', ' data3', ]
    assert list(clean_lines(conf, rstrip=False)) == ['data1 #data1\n', 'data2\n', 'data3\n', ]
    assert list(clean_lines(conf, remove_empty=False)) == ['data1 #data1', 'data2', '', 'data3', ]
    assert list(clean_lines(conf, remove_comments=False)) == ['#comment', 'data1 #data1', 'data2', 'data3', ]


def test_format_line():
    data = dict(foo='bar baz')
    assert format_line('', data) == ''
    assert format_line('{foo}', data) == 'bar baz'
    assert format_line('foo{foo}foo', data) == 'foobar bazfoo'


def test_format_line_erroneous():
    data = dict()
    with pytest.raises(PlaceholderError):
        assert format_line('{invalid}', data)
    with pytest.raises(PlaceholderError):
        assert format_line('{}', data)
    with pytest.raises(PlaceholderError):
        assert format_line('{now!r}', data)
    with pytest.raises(PlaceholderError):
        assert format_line('{now.__class__.__module__.__builtins__}', data)


def test_replace_placeholders():
    now = datetime.now()
    assert " " not in replace_placeholders('{now}')
    assert int(replace_placeholders('{now:%Y}')) == now.year


def test_override_placeholders():
    assert replace_placeholders('{uuid4}', overrides={'uuid4': "overridden"}) == "overridden"


def working_swidth():
    return platform.swidth('선') == 2


@pytest.mark.skipif(not working_swidth(), reason='swidth() is not supported / active')
def test_swidth_slice():
    string = '나윤선나윤선나윤선나윤선나윤선'
    assert swidth_slice(string, 1) == ''
    assert swidth_slice(string, -1) == ''
    assert swidth_slice(string, 4) == '나윤'
    assert swidth_slice(string, -4) == '윤선'


@pytest.mark.skipif(not working_swidth(), reason='swidth() is not supported / active')
def test_swidth_slice_mixed_characters():
    string = '나윤a선나윤선나윤선나윤선나윤선'
    assert swidth_slice(string, 5) == '나윤a'
    assert swidth_slice(string, 6) == '나윤a'


def test_safe_timestamps():
    if SUPPORT_32BIT_PLATFORMS:
        # ns fit into int64
        assert safe_ns(2 ** 64) <= 2 ** 63 - 1
        assert safe_ns(-1) == 0
        # s fit into int32
        assert safe_s(2 ** 64) <= 2 ** 31 - 1
        assert safe_s(-1) == 0
        # datetime won't fall over its y10k problem
        beyond_y10k = 2 ** 100
        with pytest.raises(OverflowError):
            datetime.utcfromtimestamp(beyond_y10k)
        assert datetime.utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2038, 1, 1)
        assert datetime.utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2038, 1, 1)
    else:
        # ns fit into int64
        assert safe_ns(2 ** 64) <= 2 ** 63 - 1
        assert safe_ns(-1) == 0
        # s are so that their ns conversion fits into int64
        assert safe_s(2 ** 64) * 1000000000 <= 2 ** 63 - 1
        assert safe_s(-1) == 0
        # datetime won't fall over its y10k problem
        beyond_y10k = 2 ** 100
        with pytest.raises(OverflowError):
            datetime.utcfromtimestamp(beyond_y10k)
        assert datetime.utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2262, 1, 1)
        assert datetime.utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2262, 1, 1)


class TestPopenWithErrorHandling:
    @pytest.mark.skipif(not shutil.which('test'), reason='"test" binary is needed')
    def test_simple(self):
        proc = popen_with_error_handling('test 1')
        assert proc.wait() == 0

    @pytest.mark.skipif(shutil.which('borg-foobar-test-notexist'), reason='"borg-foobar-test-notexist" binary exists (somehow?)')
    def test_not_found(self):
        proc = popen_with_error_handling('borg-foobar-test-notexist 1234')
        assert proc is None

    @pytest.mark.parametrize('cmd', (
            'mismatched "quote',
            'foo --bar="baz',
            ''
    ))
    def test_bad_syntax(self, cmd):
        proc = popen_with_error_handling(cmd)
        assert proc is None

    def test_shell(self):
        with pytest.raises(AssertionError):
            popen_with_error_handling('', shell=True)


def test_dash_open():
    assert dash_open('-', 'r') is sys.stdin
    assert dash_open('-', 'w') is sys.stdout
    assert dash_open('-', 'rb') is sys.stdin.buffer
    assert dash_open('-', 'wb') is sys.stdout.buffer
