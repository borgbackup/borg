import os
import shutil
import sys
import tempfile
from unittest.mock import patch

from ..hashindex import NSIndex
from ..helpers import Location, IntegrityError
from ..locking import Lock, LockFailed
from ..remote import RemoteRepository, InvalidRPCMethod
from ..repository import Repository, LoggedIO, TAG_DELETE, MAX_DATA_SIZE
from . import BaseTestCase
from .hashindex import H


UNSPECIFIED = object()  # for default values where we can't use None


class RepositoryTestCaseBase(BaseTestCase):
    key_size = 32
    exclusive = True

    def open(self, create=False, exclusive=UNSPECIFIED):
        if exclusive is UNSPECIFIED:
            exclusive = self.exclusive
        return Repository(os.path.join(self.tmppath, 'repository'), exclusive=exclusive, create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)
        self.repository.__enter__()

    def tearDown(self):
        self.repository.close()
        shutil.rmtree(self.tmppath)

    def reopen(self, exclusive=UNSPECIFIED):
        if self.repository:
            self.repository.close()
        self.repository = self.open(exclusive=exclusive)


class RepositoryTestCase(RepositoryTestCaseBase):

    def test1(self):
        for x in range(100):
            self.repository.put(H(x), b'SOMEDATA')
        key50 = H(50)
        self.assert_equal(self.repository.get(key50), b'SOMEDATA')
        self.repository.delete(key50)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(key50))
        self.repository.commit()
        self.repository.close()
        with self.open() as repository2:
            self.assert_raises(Repository.ObjectNotFound, lambda: repository2.get(key50))
            for x in range(100):
                if x == 50:
                    continue
                self.assert_equal(repository2.get(H(x)), b'SOMEDATA')

    def test2(self):
        """Test multiple sequential transactions
        """
        self.repository.put(H(0), b'foo')
        self.repository.put(H(1), b'foo')
        self.repository.commit()
        self.repository.delete(H(0))
        self.repository.put(H(1), b'bar')
        self.repository.commit()
        self.assert_equal(self.repository.get(H(1)), b'bar')

    def test_consistency(self):
        """Test cache consistency
        """
        self.repository.put(H(0), b'foo')
        self.assert_equal(self.repository.get(H(0)), b'foo')
        self.repository.put(H(0), b'foo2')
        self.assert_equal(self.repository.get(H(0)), b'foo2')
        self.repository.put(H(0), b'bar')
        self.assert_equal(self.repository.get(H(0)), b'bar')
        self.repository.delete(H(0))
        self.assert_raises(Repository.ObjectNotFound, lambda: self.repository.get(H(0)))

    def test_consistency2(self):
        """Test cache consistency2
        """
        self.repository.put(H(0), b'foo')
        self.assert_equal(self.repository.get(H(0)), b'foo')
        self.repository.commit()
        self.repository.put(H(0), b'foo2')
        self.assert_equal(self.repository.get(H(0)), b'foo2')
        self.repository.rollback()
        self.assert_equal(self.repository.get(H(0)), b'foo')

    def test_overwrite_in_same_transaction(self):
        """Test cache consistency2
        """
        self.repository.put(H(0), b'foo')
        self.repository.put(H(0), b'foo2')
        self.repository.commit()
        self.assert_equal(self.repository.get(H(0)), b'foo2')

    def test_single_kind_transactions(self):
        # put
        self.repository.put(H(0), b'foo')
        self.repository.commit()
        self.repository.close()
        # replace
        self.repository = self.open()
        with self.repository:
            self.repository.put(H(0), b'bar')
            self.repository.commit()
        # delete
        self.repository = self.open()
        with self.repository:
            self.repository.delete(H(0))
            self.repository.commit()

    def test_list(self):
        for x in range(100):
            self.repository.put(H(x), b'SOMEDATA')
        all = self.repository.list()
        self.assert_equal(len(all), 100)
        first_half = self.repository.list(limit=50)
        self.assert_equal(len(first_half), 50)
        self.assert_equal(first_half, all[:50])
        second_half = self.repository.list(marker=first_half[-1])
        self.assert_equal(len(second_half), 50)
        self.assert_equal(second_half, all[50:])
        self.assert_equal(len(self.repository.list(limit=50)), 50)

    def test_max_data_size(self):
        max_data = b'x' * MAX_DATA_SIZE
        self.repository.put(H(0), max_data)
        self.assert_equal(self.repository.get(H(0)), max_data)
        self.assert_raises(IntegrityError,
                           lambda: self.repository.put(H(1), max_data + b'x'))


class RepositoryCommitTestCase(RepositoryTestCaseBase):

    def add_keys(self):
        self.repository.put(H(0), b'foo')
        self.repository.put(H(1), b'bar')
        self.repository.put(H(3), b'bar')
        self.repository.commit()
        self.repository.put(H(1), b'bar2')
        self.repository.put(H(2), b'boo')
        self.repository.delete(H(3))

    def test_replay_of_missing_index(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        self.reopen()
        with self.repository:
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
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)

    def test_crash_before_write_index(self):
        self.add_keys()
        self.repository.write_index = None
        try:
            self.repository.commit()
        except TypeError:
            pass
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)

    def test_replay_lock_upgrade_old(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(Lock, 'upgrade', side_effect=LockFailed) as upgrade:
            self.reopen(exclusive=None)  # simulate old client that always does lock upgrades
            with self.repository:
                # the repo is only locked by a shared read lock, but to replay segments,
                # we need an exclusive write lock - check if the lock gets upgraded.
                self.assert_raises(LockFailed, lambda: len(self.repository))
                upgrade.assert_called_once_with()

    def test_replay_lock_upgrade(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(Lock, 'upgrade', side_effect=LockFailed) as upgrade:
            self.reopen(exclusive=False)  # current client usually does not do lock upgrade, except for replay
            with self.repository:
                # the repo is only locked by a shared read lock, but to replay segments,
                # we need an exclusive write lock - check if the lock gets upgraded.
                self.assert_raises(LockFailed, lambda: len(self.repository))
                upgrade.assert_called_once_with()

    def test_crash_before_deleting_compacted_segments(self):
        self.add_keys()
        self.repository.io.delete_segment = None
        try:
            self.repository.commit()
        except TypeError:
            pass
        self.reopen()
        with self.repository:
            self.assert_equal(len(self.repository), 3)
            self.assert_equal(self.repository.check(), True)
            self.assert_equal(len(self.repository), 3)

    def test_ignores_commit_tag_in_data(self):
        self.repository.put(H(0), LoggedIO.COMMIT)
        self.reopen()
        with self.repository:
            io = self.repository.io
            assert not io.is_committed_segment(io.get_latest_segment())

    def test_moved_deletes_are_tracked(self):
        self.repository.put(H(1), b'1')
        self.repository.put(H(2), b'2')
        self.repository.commit()
        self.repository.delete(H(1))
        self.repository.commit()
        last_segment = self.repository.io.get_latest_segment()
        num_deletes = 0
        for tag, key, offset, data in self.repository.io.iter_objects(last_segment, include_data=True):
            if tag == TAG_DELETE:
                assert key == H(1)
                num_deletes += 1
        assert num_deletes == 1
        assert last_segment in self.repository.compact
        self.repository.put(H(3), b'3')
        self.repository.commit()
        assert last_segment not in self.repository.compact
        assert not self.repository.io.segment_exists(last_segment)
        last_segment = self.repository.io.get_latest_segment()
        for tag, key, offset in self.repository.io.iter_objects(last_segment):
            assert tag != TAG_DELETE


class RepositoryAppendOnlyTestCase(RepositoryTestCaseBase):
    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, 'repository'), exclusive=True, create=create, append_only=True)

    def test_destroy_append_only(self):
        # Can't destroy append only repo (via the API)
        with self.assert_raises(ValueError):
            self.repository.destroy()
        assert self.repository.append_only

    def test_append_only(self):
        def segments_in_repository():
            return len(list(self.repository.io.segment_iterator()))
        self.repository.put(H(0), b'foo')
        self.repository.commit()

        self.repository.append_only = False
        assert segments_in_repository() == 1
        self.repository.put(H(0), b'foo')
        self.repository.commit()
        # normal: compact squashes the data together, only one segment
        assert segments_in_repository() == 1

        self.repository.append_only = True
        assert segments_in_repository() == 1
        self.repository.put(H(0), b'foo')
        self.repository.commit()
        # append only: does not compact, only new segments written
        assert segments_in_repository() == 2


class RepositoryCheckTestCase(RepositoryTestCaseBase):

    def list_indices(self):
        return [name for name in os.listdir(os.path.join(self.tmppath, 'repository')) if name.startswith('index.')]

    def check(self, repair=False, status=True):
        self.assert_equal(self.repository.check(repair=repair), status)
        # Make sure no tmp files are left behind
        self.assert_equal([name for name in os.listdir(os.path.join(self.tmppath, 'repository')) if 'tmp' in name], [], 'Found tmp files')

    def get_objects(self, *ids):
        for id_ in ids:
            self.repository.get(H(id_))

    def add_objects(self, segments):
        for ids in segments:
            for id_ in ids:
                self.repository.put(H(id_), b'data')
            self.repository.commit()

    def get_head(self):
        return sorted(int(n) for n in os.listdir(os.path.join(self.tmppath, 'repository', 'data', '0')) if n.isdigit())[-1]

    def open_index(self):
        return NSIndex.read(os.path.join(self.tmppath, 'repository', 'index.{}'.format(self.get_head())))

    def corrupt_object(self, id_):
        idx = self.open_index()
        segment, offset = idx[H(id_)]
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
        self.add_objects([[1, 2, 3], [4, 5], [6]])
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
        self.repository.put(H(0), b'data')
        self.repository.put(H(0), b'data2')
        # Simulate a crash before compact
        with patch.object(Repository, 'compact_segments') as compact:
            self.repository.commit()
            compact.assert_called_once_with(save_space=False)
        self.reopen()
        with self.repository:
            self.check(repair=True)
            self.assert_equal(self.repository.get(H(0)), b'data2')


class RemoteRepositoryTestCase(RepositoryTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')),
                                exclusive=True, create=create)

    def test_invalid_rpc(self):
        self.assert_raises(InvalidRPCMethod, lambda: self.repository.call('__init__', None))

    def test_ssh_cmd(self):
        assert self.repository.ssh_cmd(Location('example.com:foo')) == ['ssh', 'example.com']
        assert self.repository.ssh_cmd(Location('ssh://example.com/foo')) == ['ssh', 'example.com']
        assert self.repository.ssh_cmd(Location('ssh://user@example.com/foo')) == ['ssh', 'user@example.com']
        assert self.repository.ssh_cmd(Location('ssh://user@example.com:1234/foo')) == ['ssh', '-p', '1234', 'user@example.com']
        os.environ['BORG_RSH'] = 'ssh --foo'
        assert self.repository.ssh_cmd(Location('example.com:foo')) == ['ssh', '--foo', 'example.com']

    def test_borg_cmd(self):
        class MockArgs:
            remote_path = 'borg'
            umask = 0o077

        assert self.repository.borg_cmd(None, testing=True) == [sys.executable, '-m', 'borg.archiver', 'serve']
        args = MockArgs()
        # note: test logger is on info log level, so --info gets added automagically
        assert self.repository.borg_cmd(args, testing=False) == ['borg', 'serve', '--umask=077', '--info']
        args.remote_path = 'borg-0.28.2'
        assert self.repository.borg_cmd(args, testing=False) == ['borg-0.28.2', 'serve', '--umask=077', '--info']


class RemoteRepositoryCheckTestCase(RepositoryCheckTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')),
                                exclusive=True, create=create)

    def test_crash_before_compact(self):
        # skip this test, we can't mock-patch a Repository class in another process!
        pass
