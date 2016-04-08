import io
import logging
import os
import shutil
import sys
import tempfile
from unittest.mock import patch

from ..hashindex import NSIndex
from ..helpers import Location, IntegrityError, InternalOSError
from ..locking import UpgradableLock, LockFailed
from ..remote import RemoteRepository, InvalidRPCMethod, ConnectionClosedWithHint
from ..repository import Repository, LoggedIO, MAGIC
from . import BaseTestCase


class RepositoryTestCaseBase(BaseTestCase):
    key_size = 32

    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, 'repository'), create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)
        self.repository.__enter__()

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
        with self.open() as repository2:
            self.assert_raises(Repository.ObjectNotFound, lambda: repository2.get(key50))
            for x in range(100):
                if x == 50:
                    continue
                self.assert_equal(repository2.get(('%-32d' % x).encode('ascii')), b'SOMEDATA')

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
        with self.repository:
            self.repository.put(b'00000000000000000000000000000000', b'bar')
            self.repository.commit()
        # delete
        self.repository = self.open()
        with self.repository:
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


class LocalRepositoryTestCase(RepositoryTestCaseBase):
    # test case that doesn't work with remote repositories

    def _assert_sparse(self):
        # The superseded 123456... PUT
        assert self.repository.compact[0] == 41 + 9
        # The DELETE issued by the superseding PUT (or issued directly)
        assert self.repository.compact[2] == 41
        self.repository._rebuild_sparse(0)
        assert self.repository.compact[0] == 41 + 9

    def test_sparse1(self):
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000001', b'123456789')
        self.repository.commit()
        self.repository.put(b'00000000000000000000000000000001', b'bar')
        self._assert_sparse()

    def test_sparse2(self):
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000001', b'123456789')
        self.repository.commit()
        self.repository.delete(b'00000000000000000000000000000001')
        self._assert_sparse()

    def test_sparse_delete(self):
        self.repository.put(b'00000000000000000000000000000000', b'1245')
        self.repository.delete(b'00000000000000000000000000000000')
        self.repository.io._write_fd.sync()

        # The on-line tracking works on a per-object basis...
        assert self.repository.compact[0] == 41 + 41 + 4
        self.repository._rebuild_sparse(0)
        # ...while _rebuild_sparse can mark whole segments as completely sparse (which then includes the segment magic)
        assert self.repository.compact[0] == 41 + 41 + 4 + len(MAGIC)

        self.repository.commit()
        assert 0 not in [segment for segment, _ in self.repository.io.segment_iterator()]


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

    def test_replay_of_readonly_repository(self):
        self.add_keys()
        for name in os.listdir(self.repository.path):
            if name.startswith('index.'):
                os.unlink(os.path.join(self.repository.path, name))
        with patch.object(UpgradableLock, 'upgrade', side_effect=LockFailed) as upgrade:
            self.reopen()
            with self.repository:
                self.assert_raises(LockFailed, lambda: len(self.repository))
                upgrade.assert_called_once_with()

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
        self.repository.put(b'0' * 32, LoggedIO.COMMIT)
        self.reopen()
        with self.repository:
            io = self.repository.io
            assert not io.is_committed_segment(io.get_latest_segment())


class RepositoryAppendOnlyTestCase(RepositoryTestCaseBase):
    def test_destroy_append_only(self):
        # Can't destroy append only repo (via the API)
        self.repository.append_only = True
        with self.assert_raises(ValueError):
            self.repository.destroy()

    def test_append_only(self):
        def segments_in_repository():
            return len(list(self.repository.io.segment_iterator()))
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()

        self.repository.append_only = False
        assert segments_in_repository() == 2
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()
        # normal: compact squashes the data together, only one segment
        assert segments_in_repository() == 4

        self.repository.append_only = True
        assert segments_in_repository() == 4
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()
        # append only: does not compact, only new segments written
        assert segments_in_repository() == 6


class RepositoryAuxiliaryCorruptionTestCase(RepositoryTestCaseBase):
    def setUp(self):
        super().setUp()
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()
        self.repository.close()

    def do_commit(self):
        with self.repository:
            self.repository.put(b'00000000000000000000000000000000', b'fox')
            self.repository.commit()

    def test_corrupted_hints(self):
        with open(os.path.join(self.repository.path, 'hints.0'), 'ab') as fp:
            fp.write(b'123456789')
        self.do_commit()

    def test_deleted_hints(self):
        os.unlink(os.path.join(self.repository.path, 'hints.0'))
        self.do_commit()

    def test_unreadable_hints(self):
        hints = os.path.join(self.repository.path, 'hints.0')
        os.unlink(hints)
        os.mkdir(hints)
        with self.assert_raises(InternalOSError):
            self.do_commit()

    def test_index(self):
        with open(os.path.join(self.repository.path, 'index.0'), 'wb') as fp:
            fp.write(b'123456789')
        self.do_commit()

    def test_index_outside_transaction(self):
        with open(os.path.join(self.repository.path, 'index.0'), 'wb') as fp:
            fp.write(b'123456789')
        with self.repository:
            assert len(self.repository) == 1


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
        self.delete_segment(2)
        self.repository.rollback()
        self.check(repair=True, status=True)
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_missing_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        self.delete_segment(3)
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_corrupted_commit_segment(self):
        self.add_objects([[1, 2, 3], [4, 5, 6]])
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', '3'), 'r+b') as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b'X')
        self.assert_raises(Repository.ObjectNotFound, lambda: self.get_objects(4))
        self.check(status=True)
        self.get_objects(3)
        self.assert_equal(set([1, 2, 3]), self.list_objects())

    def test_repair_no_commits(self):
        self.add_objects([[1, 2, 3]])
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', '1'), 'r+b') as fd:
            fd.seek(-1, os.SEEK_END)
            fd.write(b'X')
        self.assert_raises(Repository.CheckNeeded, lambda: self.get_objects(4))
        self.check(status=False)
        self.check(status=False)
        self.assert_equal(self.list_indices(), ['index.1'])
        self.check(repair=True, status=True)
        self.assert_equal(self.list_indices(), ['index.3'])
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
        self.assert_equal(self.list_indices(), ['index.3'])
        self.rename_index('index.100')
        self.check(status=True)
        self.assert_equal(self.list_indices(), ['index.3'])
        self.get_objects(4)
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())

    def test_crash_before_compact(self):
        self.repository.put(bytes(32), b'data')
        self.repository.put(bytes(32), b'data2')
        # Simulate a crash before compact
        with patch.object(Repository, 'compact_segments') as compact:
            self.repository.commit()
            compact.assert_called_once_with(save_space=False)
        self.reopen()
        with self.repository:
            self.check(repair=True)
            self.assert_equal(self.repository.get(bytes(32)), b'data2')


class RemoteRepositoryTestCase(RepositoryTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

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
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

    def test_crash_before_compact(self):
        # skip this test, we can't mock-patch a Repository class in another process!
        pass


class RemoteRepositoryLoggingStub(RemoteRepository):
    """ run a remote command that just prints a logging-formatted message to
    stderr, and stub out enough of RemoteRepository to avoid the resulting
    exceptions """
    def __init__(self, *args, **kw):
        self.msg = kw.pop('msg')
        super().__init__(*args, **kw)

    def borg_cmd(self, cmd, testing):
        return [sys.executable, '-c', 'import sys; print("{}", file=sys.stderr)'.format(self.msg), ]

    def __del__(self):
        # clean up from exception without triggering assert
        if self.p:
            self.close()


class RemoteRepositoryLoggerTestCase(RepositoryTestCaseBase):
    def setUp(self):
        self.location = Location('__testsuite__:/doesntexist/repo')
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        logging.getLogger().handlers[:] = [self.handler]
        logging.getLogger('borg.repository').handlers[:] = []
        logging.getLogger('borg.repository.foo').handlers[:] = []

    def tearDown(self):
        pass

    def create_repository(self, msg):
        try:
            RemoteRepositoryLoggingStub(self.location, msg=msg)
        except ConnectionClosedWithHint:
            # stub is dumb, so this exception expected
            pass

    def test_old_format_messages(self):
        self.handler.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

        self.create_repository("$LOG INFO Remote: old format message")
        self.assert_equal(self.stream.getvalue(), 'Remote: old format message\n')

    def test_new_format_messages(self):
        self.handler.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)

        self.create_repository("$LOG INFO borg.repository Remote: new format message")
        self.assert_equal(self.stream.getvalue(), 'Remote: new format message\n')

    def test_remote_messages_screened(self):
        # default borg config for root logger
        self.handler.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)

        self.create_repository("$LOG INFO borg.repository Remote: new format info message")
        self.assert_equal(self.stream.getvalue(), '')

    def test_info_to_correct_local_child(self):
        logging.getLogger('borg.repository').setLevel(logging.INFO)
        logging.getLogger('borg.repository.foo').setLevel(logging.INFO)
        # default borg config for root logger
        self.handler.setLevel(logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)

        child_stream = io.StringIO()
        child_handler = logging.StreamHandler(child_stream)
        child_handler.setLevel(logging.INFO)
        logging.getLogger('borg.repository').handlers[:] = [child_handler]
        foo_stream = io.StringIO()
        foo_handler = logging.StreamHandler(foo_stream)
        foo_handler.setLevel(logging.INFO)
        logging.getLogger('borg.repository.foo').handlers[:] = [foo_handler]

        self.create_repository("$LOG INFO borg.repository Remote: new format child message")
        self.assert_equal(foo_stream.getvalue(), '')
        self.assert_equal(child_stream.getvalue(), 'Remote: new format child message\n')
        self.assert_equal(self.stream.getvalue(), '')
