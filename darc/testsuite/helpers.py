from datetime import datetime
from darc.helpers import Location, format_timedelta, IncludePattern
from darc.testsuite import DarcTestCase


class LocationTestCase(DarcTestCase):

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
            "Location(proto='ssh', user='user', host='host', port=22, path='/some/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('mybackup.darc::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='mybackup.darc', archive='archive')"
        )
        self.assert_equal(
            repr(Location('/some/absolute/path::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='/some/absolute/path', archive='archive')"
        )
        self.assert_equal(
            repr(Location('some/relative/path::archive')),
            "Location(proto='file', user=None, host=None, port=None, path='some/relative/path', archive='archive')"
        )


class FormatTimedeltaTestCase(DarcTestCase):

    def test(self):
        t0 = datetime(2001, 1, 1, 10, 20, 3, 0)
        t1 = datetime(2001, 1, 1, 12, 20, 4, 100000)
        self.assert_equal(
            format_timedelta(t1 - t0),
            '2 hours 1.10 seconds'
        )


class PatternTestCase(DarcTestCase):

    def test(self):
        py = IncludePattern('*.py')
        foo = IncludePattern('/foo')
        self.assert_equal(py.match('/foo/foo.py'), True)
        self.assert_equal(py.match('/bar/foo.java'), False)
        self.assert_equal(foo.match('/foo/foo.py'), True)
        self.assert_equal(foo.match('/bar/foo.java'), False)
        self.assert_equal(foo.match('/foobar/foo.py'), False)
        self.assert_equal(foo.match('/foo'), True)
