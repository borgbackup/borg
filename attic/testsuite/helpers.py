from datetime import datetime
import os
import tempfile
import unittest
from attic.helpers import Location, format_timedelta, IncludePattern, ExcludePattern, make_path_safe, UpgradableLock
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

    def test(self):
        self.assert_equal(IncludePattern('/usr').match('/usr'), True)
        self.assert_equal(IncludePattern('/usr').match('/usr/bin'), True)
        self.assert_equal(IncludePattern('/usr').match('/usrbin'), False)
        self.assert_equal(ExcludePattern('*.py').match('foo.py'), True)
        self.assert_equal(ExcludePattern('*.py').match('foo.pl'), False)
        self.assert_equal(ExcludePattern('/tmp').match('/tmp'), True)
        self.assert_equal(ExcludePattern('/tmp').match('/tmp/foo'), True)
        self.assert_equal(ExcludePattern('/tmp').match('/tmofoo'), False)


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
