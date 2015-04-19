import hashlib
from time import mktime, strptime
from datetime import datetime, timezone, timedelta
import os
import tempfile
import unittest
from attic.helpers import adjust_patterns, exclude_path, Location, format_timedelta, IncludePattern, ExcludePattern, make_path_safe, UpgradableLock, prune_within, prune_split, to_localtime, \
    StableDict, int_to_bigint, bigint_to_int, parse_timestamp
from attic.testsuite import AtticTestCase
import msgpack


class BigIntTestCase(AtticTestCase):

    def test_bigint(self):
        self.assert_equal(int_to_bigint(0), 0)
        self.assert_equal(int_to_bigint(2**63-1), 2**63-1)
        self.assert_equal(int_to_bigint(-2**63+1), -2**63+1)
        self.assert_equal(int_to_bigint(2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\x00')
        self.assert_equal(int_to_bigint(-2**63), b'\x00\x00\x00\x00\x00\x00\x00\x80\xff')
        self.assert_equal(bigint_to_int(int_to_bigint(-2**70)), -2**70)
        self.assert_equal(bigint_to_int(int_to_bigint(2**70)), 2**70)


class LocationTestCase(AtticTestCase):

    def test(self):
        self.assert_equal(
            repr(Location('ssh://user@host:1234/some/path::archive')),
            "Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('file:///some/path::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('user@host:/some/path::archive')),
            "Location(proto='ssh', user='user', host='host', port=None, path='/some/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('mybackup.attic::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='mybackup.attic', archive='archive')"
        )
        self.assert_equal(
            repr(Location('/some/absolute/path::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('some/relative/path::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        )
        self.assert_raises(ValueError, lambda: Location('ssh://localhost:22/path:archive'))

    def test_canonical_path(self):
        locations = ['some/path::archive', 'file://some/path::archive', 'host:some/path::archive',
                     'host:~user/some/path::archive', 'ssh://host/some/path::archive',
                     'ssh://user@host:1234/some/path::archive']
        for location in locations:
            self.assert_equal(Location(location).canonical_path(),
                              Location(Location(location).canonical_path()).canonical_path())


class FormatTimedeltaTestCase(AtticTestCase):

    def test(self):
        t0 = datetime(2001, 1, 1, 10, 20, 3, 0)
        t1 = datetime(2001, 1, 1, 12, 20, 4, 100000)
        self.assert_equal(
            format_timedelta(t1 - t0),
            '2 hours 1.10 seconds'
        )


class PatternTestCase(AtticTestCase):

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


class MakePathSafeTestCase(AtticTestCase):

    def test(self):
        self.assert_equal(make_path_safe('/foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/f/bar'), 'f/bar')
        self.assert_equal(make_path_safe('fo/bar'), 'fo/bar')
        self.assert_equal(make_path_safe('../foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('../../foo/bar'), 'foo/bar')
        self.assert_equal(make_path_safe('/'), '.')
        self.assert_equal(make_path_safe('/'), '.')

class UpgradableLockTestCase(AtticTestCase):

    def test(self):
        file = tempfile.NamedTemporaryFile()
        lock = UpgradableLock(file.name)
        lock.upgrade()
        lock.upgrade()
        lock.release()

    @unittest.skipIf(os.getuid() == 0, 'Root can always open files for writing')
    def test_read_only_lock_file(self):
        file = tempfile.NamedTemporaryFile()
        os.chmod(file.name, 0o444)
        lock = UpgradableLock(file.name)
        self.assert_raises(UpgradableLock.WriteLockFailed, lock.upgrade)
        lock.release()


class MockArchive(object):

    def __init__(self, ts):
        self.ts = ts

    def __repr__(self):
        return repr(self.ts)


class PruneSplitTestCase(AtticTestCase):

    def test(self):

        def local_to_UTC(month, day):
            'Convert noon on the month and day in 2013 to UTC.'
            seconds = mktime(strptime('2013-%02d-%02d 12:00' % (month, day), '%Y-%m-%d %H:%M'))
            return datetime.fromtimestamp(seconds, tz=timezone.utc)

        def subset(lst, indices):
            return {lst[i] for i in indices}

        def dotest(test_archives, n, skip, indices):
            for ta in test_archives, reversed(test_archives):
                self.assert_equal(set(prune_split(ta, '%Y-%m', n, skip)),
                                  subset(test_archives, indices))
            
        test_pairs = [(1,1), (2,1), (2,28), (3,1), (3,2), (3,31), (5,1)]
        test_dates = [local_to_UTC(month, day) for month, day in test_pairs]
        test_archives = [MockArchive(date) for date in test_dates]

        dotest(test_archives, 3, [], [6, 5, 2])
        dotest(test_archives, -1, [], [6, 5, 2, 0])
        dotest(test_archives, 3, [test_archives[6]], [5, 2, 0])
        dotest(test_archives, 3, [test_archives[5]], [6, 2, 0])
        dotest(test_archives, 3, [test_archives[4]], [6, 5, 2])
        dotest(test_archives, 0, [], [])


class PruneWithinTestCase(AtticTestCase):

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

        dotest(test_archives, '1H',  [0])
        dotest(test_archives, '2H',  [0, 1])
        dotest(test_archives, '3H',  [0, 1, 2])
        dotest(test_archives, '24H', [0, 1, 2, 3])
        dotest(test_archives, '26H', [0, 1, 2, 3, 4])
        dotest(test_archives, '2d',  [0, 1, 2, 3, 4])
        dotest(test_archives, '50H', [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '3d',  [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1w',  [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1m',  [0, 1, 2, 3, 4, 5])
        dotest(test_archives, '1y',  [0, 1, 2, 3, 4, 5])


class StableDictTestCase(AtticTestCase):

    def test(self):
        d = StableDict(foo=1, bar=2, boo=3, baz=4)
        self.assert_equal(list(d.items()), [('bar', 2), ('baz', 4), ('boo', 3), ('foo', 1)])
        self.assert_equal(hashlib.md5(msgpack.packb(d)).hexdigest(), 'fc78df42cd60691b3ac3dd2a2b39903f')


class TestParseTimestamp(AtticTestCase):

    def test(self):
        self.assert_equal(parse_timestamp('2015-04-19T20:25:00.226410'), datetime(2015, 4, 19, 20, 25, 0, 226410, timezone.utc))
        self.assert_equal(parse_timestamp('2015-04-19T20:25:00'), datetime(2015, 4, 19, 20, 25, 0, 0, timezone.utc))
