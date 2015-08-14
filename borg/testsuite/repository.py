import os
import shutil
import tempfile

from mock import patch

from ..hashindex import NSIndex
from ..helpers import Location, IntegrityError
from ..locking import UpgradableLock
from ..remote import RemoteRepository, InvalidRPCMethod
from ..repository import Repository
from . import BaseTestCase


class RepositoryTestCaseBase(BaseTestCase):
    key_size = 32

    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, 'repository'), create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)

    def tearDown(self):
        self.repository.close()
        shutil.rmtree(self.tmppath)

    def reopen(self):
        if self.repository:
            self.repository.close()
        self.repository = self.open()


class RepositoryTestCase(RepositoryTestCaseBase):

    def test1(self):
        for x in range(100):
            self.repository.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
        key50 = ('%-32d' % 50).encode('ascii')
        self.assert_equal(self.repository.get(key50), b'SOMEDATA')
        self.repository.delete(key50)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(key50))
        self.repository.commit()
        self.repository.close()
        repository2 = self.open()
        self.assert_raises(Repository.ObjectNotFound, lambda: repository2.get(key50))
        for x in range(100):
            if x == 50:
                continue
            self.assert_equal(repository2.get(('%-32d' % x).encode('ascii')), b'SOMEDATA')
        repository2.close()

    def test2(self):
        """Test multiple sequential transactions
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000001', b'foo')
        self.repository.commit()
        self.repository.delete(b'00000000000000000000000000000000')
        self.repository.put(b'00000000000000000000000000000001', b'bar')
        self.repository.commit()
        self.assert_equal(self.repository.get(b'00000000000000000000000000000001'), b'bar')

    def test_consistency(self):
        """Test cache consistency
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')
        self.repository.put(b'00000000000000000000000000000000', b'foo2')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo2')
        self.repository.put(b'00000000000000000000000000000000', b'bar')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'bar')
        self.repository.delete(b'00000000000000000000000000000000')
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(b'00000000000000000000000000000000'))

    def test_consistency2(self):
        """Test cache consistency2
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')
        self.repository.commit()
        self.repository.put(b'00000000000000000000000000000000', b'foo2')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo2')
        self.repository.rollback()
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')

    def test_overwrite_in_same_transaction(self):
        """Test cache consistency2
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000000', b'foo2')
        self.repository.commit()
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo2')

    def test_single_kind_transactions(self):
        # put
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()
        self.repository.close()
        # replace
        self.repository = self.open()
        self.repository.put(b'00000000000000000000000000000000', b'bar')
        self.repository.commit()
        self.repository.close()
        # delete
        self.repository = self.open()
        self.repository.delete(b'00000000000000000000000000000000')
        self.repository.commit()

    def test_list(self):
        for x in range(100):
            self.repository.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
        all = self.repository.list()
        self.assert_equal(len(all), 100)
        first_half = self.repository.list(limit=50)
        self.assert_equal(len(first_half), 50)
        self.assert_equal(first_half, all[:50])
        second_half = self.repository.list(marker=first_half[-1])
        self.assert_equal(len(second_half), 50)
        self.assert_equal(second_half, all[50:])
        self.assert_equal(len(self.repository.list(limit=50)), 50)


class RepositoryCommitTestCase(RepositoryTestCaseBase):

    def add_keys(self):
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000001', b'bar')
        self.repository.put(b'00000000000000000000000000000003', b'bar')
        self.repository.commit()
        self.repository.put(b'00000000000000000000000000000001', b'bar2')
        self.repository.put(b'00000000000000000000000000000002', b'boo')
        self.repository.delete(b'00000000000000000000000000000003')

    def test_replay_of_missing_index(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        self.reopen()
        self.assert_equal(len(self.repository), 3)
        self.assert_equal(self.repository.check(), True)

    def test_crash_before_compact_segments(self):
        self.add_keys()
        self.repository.compact_segments = None
        try:
            self.repository.commit()
        except TypeError:
            pass
        self.reopen()
        self.assert_equal(len(self.repository), 3)
        self.assert_equal(self.repository.check(), True)

    def test_replay_of_readonly_repository(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(UpgradableLock, 'upgrade', side_effect=UpgradableLock.ExclusiveLockFailed) as upgrade:
            self.reopen()
            self.assert_raises(UpgradableLock.ExclusiveLockFailed, lambda: len(self.repository))
            upgrade.assert_called_once_with()

    def test_crash_before_write_index(self):
        self.add_keys()
        self.repository.write_index = None
        try:
            self.repository.commit()
        except TypeError:
            pass
        self.reopen()
        self.assert_equal(len(self.repository), 3)
        self.assert_equal(self.repository.check(), True)

    def test_crash_before_deleting_compacted_segments(self):
        self.add_keys()
        self.repository.io.delete_segment = None
        try:
            self.repository.commit()
        except TypeError:
            pass
        self.reopen()
        self.assert_equal(len(self.repository), 3)
        self.assert_equal(self.repository.check(), True)
        self.assert_equal(len(self.repository), 3)


class RepositoryCheckTestCase(RepositoryTestCaseBase):

    def list_indices(self):
        return [name for name in os.listdir(os.path.join(self.tmppath, 'repository')) if name.startswith('index.')]

    def check(self, repair=False, status=True):
        self.assert_equal(self.repository.check(repair=repair), status)
        # Make sure no tmp files are left behind
        self.assert_equal([name for name in os.listdir(os.path.join(self.tmppath, 'repository')) if 'tmp' in name], [], 'Found tmp files')

    def get_objects(self, *ids):
        for id_ in ids:
            self.repository.get(('%032d' % id_).encode('ascii'))

    def add_objects(self, segments):
        for ids in segments:
            for id_ in ids:
                self.repository.put(('%032d' % id_).encode('ascii'), b'data')
            self.repository.commit()

    def get_head(self):
        return sorted(int(n) for n in os.listdir(os.path.join(self.tmppath, 'repository', 'data', '0')) if n.isdigit())[-1]

    def open_index(self):
        return NSIndex.read(os.path.join(self.tmppath, 'repository', 'index.{}'.format(self.get_head())))

    def corrupt_object(self, id_):
        idx = self.open_index()
        segment, offset = idx[('%032d' % id_).encode('ascii')]
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', str(segment)), 'r+b') as fd:
            fd.seek(offset)
            fd.write(b'BOOM')

    def delete_segment(self, segment):
        os.unlink(os.path.join(self.tmppath, 'repository', 'data', '0', str(segment)))

    def delete_index(self):
        os.unlink(os.path.join(self.tmppath, 'repository', 'index.{}'.format(self.get_head())))

    def rename_index(self, new_name):
        os.rename(os.path.join(self.tmppath, 'repository', 'index.{}'.format(self.get_head())),
                  os.path.join(self.tmppath, 'repository', new_name))

    def list_objects(self):
        return set(int(key) for key in self.repository.list())

    def test_repair_corrupted_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())
        self.check(status=True)
        self.corrupt_object(5)
        self.assert_raises(IntegrityError, lambda: self.get_objects(5))
        self.repository.rollback()
        # Make sure a regular check does not repair anything
        self.check(status=False)
        self.check(status=False)
        # Make sure a repair actually repairs the repo
        self.check(repair=True, status=True)
        self.get_objects(4)
        self.check(status=True)
        self.assert_equal(set([1, 2, 3, 4, 6]), self.list_objects())

    def test_repair_missing_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())
        self.check(status=True)
        self.delete_segment(1)
        self.repository.rollback()
        self.check(repair=True, status=True)
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_missing_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.delete_segment(1)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_corrupted_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', '1'), 'r+b') as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b'X')
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.check(status=True)
        self.get_objects(3)
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_no_commits(self):
        self.add_objects([[1, 2, 3]])
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', '0'), 'r+b') as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b'X')
        self.assert_raises(Repository.CheckNeeded, lambda: self.get_objects(4))
        self.check(status=False)
        self.check(status=False)
        self.assert_equal(self.list_indices(), ['index.0'])
        self.check(repair=True, status=True)
        self.assert_equal(self.list_indices(), ['index.1'])
        self.check(status=True)
        self.get_objects(3)
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_missing_index(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.delete_index()
        self.check(status=True)
        self.get_objects(4)
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())

    def test_repair_index_too_new(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.assert_equal(self.list_indices(), ['index.1'])
        self.rename_index('index.100')
        self.check(status=True)
        self.assert_equal(self.list_indices(), ['index.1'])
        self.get_objects(4)
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())

    def test_crash_before_compact(self):
        self.repository.put(bytes(32), b'data')
        self.repository.put(bytes(32), b'data2')
        # Simulate a crash before compact
        with patch.object(Repository, 'compact_segments') as compact:
            self.repository.commit()
            compact.assert_called_once_with()
        self.reopen()
        self.check(repair=True)
        self.assert_equal(self.repository.get(bytes(32)), b'data2')


class RemoteRepositoryTestCase(RepositoryTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

    def test_invalid_rpc(self):
        self.assert_raises(InvalidRPCMethod, lambda: self.repository.call('__init__', None))


class RemoteRepositoryCheckTestCase(RepositoryCheckTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

    def test_crash_before_compact(self):
        # skip this test, we can't mock-patch a Repository class in another process!
        pass
