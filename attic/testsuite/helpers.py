from time import mktime, strptime
from datetime import datetime, timezone
import os
import tempfile
import unittest
from attic.helpers import adjust_patterns, exclude_path, Location, format_timedelta, IncludePattern, ExcludePattern, make_path_safe, UpgradableLock, prune_split, to_localtime
from attic.testsuite import AtticTestCase


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
        self.assert_raises(UpgradableLock.LockUpgradeFailed, lock.upgrade)
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
