import os

from ..helpers import Location
from .repository import RepositoryTestCase, RepositoryCheckTestCase
from ..remote import RemoteRepository, InvalidRPCMethod

class RemoteRepositoryTestCase(RepositoryTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

    def test_invalid_rpc(self):
        self.assert_raises(InvalidRPCMethod, lambda: self.repository.call('__init__', None))

    def test_ssh_cmd(self):
        assert self.repository.umask is not None
        assert self.repository.ssh_cmd(Location('example.com:foo')) == ['ssh', 'example.com', 'borg', 'serve'] + self.repository.umask_flag()
        assert self.repository.ssh_cmd(Location('ssh://example.com/foo')) == ['ssh', 'example.com', 'borg', 'serve'] + self.repository.umask_flag()
        assert self.repository.ssh_cmd(Location('ssh://user@example.com/foo')) == ['ssh', 'user@example.com', 'borg', 'serve'] + self.repository.umask_flag()
        assert self.repository.ssh_cmd(Location('ssh://user@example.com:1234/foo')) == ['ssh', '-p', '1234', 'user@example.com', 'borg', 'serve'] + self.repository.umask_flag()
        os.environ['BORG_RSH'] = 'ssh --foo'
        assert self.repository.ssh_cmd(Location('example.com:foo')) == ['ssh', '--foo', 'example.com', 'borg', 'serve'] + self.repository.umask_flag()


class RemoteRepositoryCheckTestCase(RepositoryCheckTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)

    def test_crash_before_compact(self):
        # skip this test, we can't mock-patch a Repository class in another process!
        pass


class RemoteArchiverTestCase(ArchiverTestCase):
    prefix = '__testsuite__:'

    def test_remote_repo_restrict_to_path(self):
        self.cmd('init', self.repository_location)
        path_prefix = os.path.dirname(self.repository_path)
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo']):
            self.assert_raises(PathNotAllowed, lambda: self.cmd('init', self.repository_location + '_1'))
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', path_prefix]):
            self.cmd('init', self.repository_location + '_2')
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo', '--restrict-to-path', path_prefix]):
            self.cmd('init', self.repository_location + '_3')
