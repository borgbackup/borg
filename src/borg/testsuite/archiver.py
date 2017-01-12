from binascii import unhexlify, b2a_base64
from configparser import ConfigParser
import errno
import os
import inspect
from datetime import datetime
from datetime import timedelta
from io import StringIO
import logging
import random
import socket
import stat
import subprocess
import sys
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
from hashlib import sha256

import msgpack
import pytest
try:
    import llfuse
except ImportError:
    pass

from .. import xattr, helpers, platform
from ..archive import Archive, ChunkBuffer, ArchiveRecreater, flags_noatime, flags_normal
from ..archiver import Archiver
from ..cache import Cache
from ..constants import *  # NOQA
from ..crypto import bytes_to_long, num_aes_blocks
from ..helpers import PatternMatcher, parse_pattern, Location, get_security_dir
from ..helpers import Chunk, Manifest
from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from ..helpers import bin_to_hex
from ..item import Item
from ..key import KeyfileKeyBase, RepoKey, KeyfileKey, Passphrase, TAMRequiredError
from ..keymanager import RepoIdMismatch, NotABorgKeyFile
from ..remote import RemoteRepository, PathNotAllowed
from ..repository import Repository
from . import has_lchflags, has_llfuse
from . import BaseTestCase, changedir, environment_variable, no_selinux
from . import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported, is_utime_fully_supported
from .platform import fakeroot_detected
from . import key


src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def exec_cmd(*args, archiver=None, fork=False, exe=None, **kw):
    if fork:
        try:
            if exe is None:
                borg = (sys.executable, '-m', 'borg.archiver')
            elif isinstance(exe, str):
                borg = (exe, )
            elif not isinstance(exe, tuple):
                raise ValueError('exe must be None, a tuple or a str')
            output = subprocess.check_output(borg + args, stderr=subprocess.STDOUT)
            ret = 0
        except subprocess.CalledProcessError as e:
            output = e.output
            ret = e.returncode
        except SystemExit as e:  # possibly raised by argparse
            output = ''
            ret = e.code
        return ret, os.fsdecode(output)
    else:
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = StringIO()
            sys.stdout = sys.stderr = output = StringIO()
            if archiver is None:
                archiver = Archiver()
            archiver.prerun_checks = lambda *args: None
            archiver.exit_code = EXIT_SUCCESS
            args = archiver.parse_args(list(args))
            ret = archiver.run(args)
            return ret, output.getvalue()
        finally:
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr


# check if the binary "borg.exe" is available (for local testing a symlink to virtualenv/bin/borg should do)
try:
    exec_cmd('help', exe='borg.exe', fork=True)
    BORG_EXES = ['python', 'binary', ]
except FileNotFoundError:
    BORG_EXES = ['python', ]


@pytest.fixture(params=BORG_EXES)
def cmd(request):
    if request.param == 'python':
        exe = None
    elif request.param == 'binary':
        exe = 'borg.exe'
    else:
        raise ValueError("param must be 'python' or 'binary'")

    def exec_fn(*args, **kw):
        return exec_cmd(*args, exe=exe, fork=True, **kw)
    return exec_fn


def test_return_codes(cmd, tmpdir):
    repo = tmpdir.mkdir('repo')
    input = tmpdir.mkdir('input')
    output = tmpdir.mkdir('output')
    input.join('test_file').write('content')
    rc, out = cmd('init', '--encryption=none', '%s' % str(repo))
    assert rc == EXIT_SUCCESS
    rc, out = cmd('create', '%s::archive' % repo, str(input))
    assert rc == EXIT_SUCCESS
    with changedir(str(output)):
        rc, out = cmd('extract', '%s::archive' % repo)
        assert rc == EXIT_SUCCESS
    rc, out = cmd('extract', '%s::archive' % repo, 'does/not/match')
    assert rc == EXIT_WARNING  # pattern did not match
    rc, out = cmd('create', '%s::archive' % repo, str(input))
    assert rc == EXIT_ERROR  # duplicate archive name


"""
test_disk_full is very slow and not recommended to be included in daily testing.
for this test, an empty, writable 16MB filesystem mounted on DF_MOUNT is required.
for speed and other reasons, it is recommended that the underlying block device is
in RAM, not a magnetic or flash disk.

assuming /tmp is a tmpfs (in memory filesystem), one can use this:
dd if=/dev/zero of=/tmp/borg-disk bs=16M count=1
mkfs.ext4 /tmp/borg-disk
mkdir /tmp/borg-mount
sudo mount /tmp/borg-disk /tmp/borg-mount

if the directory does not exist, the test will be skipped.
"""
DF_MOUNT = '/tmp/borg-mount'


@pytest.mark.skipif(not os.path.exists(DF_MOUNT), reason="needs a 16MB fs mounted on %s" % DF_MOUNT)
def test_disk_full(cmd):
    def make_files(dir, count, size, rnd=True):
        shutil.rmtree(dir, ignore_errors=True)
        os.mkdir(dir)
        if rnd:
            count = random.randint(1, count)
            if size > 1:
                size = random.randint(1, size)
        for i in range(count):
            fn = os.path.join(dir, "file%03d" % i)
            with open(fn, 'wb') as f:
                data = os.urandom(size)
                f.write(data)

    with environment_variable(BORG_CHECK_I_KNOW_WHAT_I_AM_DOING='YES'):
        mount = DF_MOUNT
        assert os.path.exists(mount)
        repo = os.path.join(mount, 'repo')
        input = os.path.join(mount, 'input')
        reserve = os.path.join(mount, 'reserve')
        for j in range(100):
            shutil.rmtree(repo, ignore_errors=True)
            shutil.rmtree(input, ignore_errors=True)
            # keep some space and some inodes in reserve that we can free up later:
            make_files(reserve, 80, 100000, rnd=False)
            rc, out = cmd('init', repo)
            if rc != EXIT_SUCCESS:
                print('init', rc, out)
            assert rc == EXIT_SUCCESS
            try:
                success, i = True, 0
                while success:
                    i += 1
                    try:
                        make_files(input, 20, 200000)
                    except OSError as err:
                        if err.errno == errno.ENOSPC:
                            # already out of space
                            break
                        raise
                    try:
                        rc, out = cmd('create', '%s::test%03d' % (repo, i), input)
                        success = rc == EXIT_SUCCESS
                        if not success:
                            print('create', rc, out)
                    finally:
                        # make sure repo is not locked
                        shutil.rmtree(os.path.join(repo, 'lock.exclusive'), ignore_errors=True)
                        os.remove(os.path.join(repo, 'lock.roster'))
            finally:
                # now some error happened, likely we are out of disk space.
                # free some space so we can expect borg to be able to work normally:
                shutil.rmtree(reserve, ignore_errors=True)
            rc, out = cmd('list', repo)
            if rc != EXIT_SUCCESS:
                print('list', rc, out)
            rc, out = cmd('check', '--repair', repo)
            if rc != EXIT_SUCCESS:
                print('check', rc, out)
            assert rc == EXIT_SUCCESS


class ArchiverTestCaseBase(BaseTestCase):
    EXE = None  # python source based
    FORK_DEFAULT = False
    prefix = ''

    def setUp(self):
        os.environ['BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
        os.environ['BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
        os.environ['BORG_RECREATE_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
        os.environ['BORG_PASSPHRASE'] = 'waytooeasyonlyfortests'
        self.archiver = not self.FORK_DEFAULT and Archiver() or None
        self.tmpdir = tempfile.mkdtemp()
        self.repository_path = os.path.join(self.tmpdir, 'repository')
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        self.keys_path = os.path.join(self.tmpdir, 'keys')
        self.cache_path = os.path.join(self.tmpdir, 'cache')
        self.exclude_file_path = os.path.join(self.tmpdir, 'excludes')
        os.environ['BORG_KEYS_DIR'] = self.keys_path
        os.environ['BORG_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.chmod(self.input_path, 0o777)  # avoid troubles with fakeroot / FUSE
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b'input/file2\n# A comment line, then a blank line\n\n')
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._old_wd)
        # note: ignore_errors=True as workaround for issue #862
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        # destroy logging configuration
        logging.Logger.manager.loggerDict.clear()

    def cmd(self, *args, **kw):
        exit_code = kw.pop('exit_code', 0)
        fork = kw.pop('fork', None)
        if fork is None:
            fork = self.FORK_DEFAULT
        ret, output = exec_cmd(*args, fork=fork, exe=self.EXE, archiver=self.archiver, **kw)
        if ret != exit_code:
            print(output)
        self.assert_equal(ret, exit_code)
        return output

    def create_src_archive(self, name):
        self.cmd('create', self.repository_location + '::' + name, src_dir)

    def open_archive(self, name):
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest, key = Manifest.load(repository)
            archive = Archive(repository, key, manifest, name)
        return archive, repository

    def open_repository(self):
        return Repository(self.repository_path, exclusive=True)

    def create_regular_file(self, name, size=0, contents=None):
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
            if contents is None:
                contents = b'X' * size
            fd.write(contents)

    def create_test_files(self):
        """Create a minimal test case including all supported file types
        """
        # File
        self.create_regular_file('empty', size=0)
        # next code line raises OverflowError on 32bit cpu (raspberry pi 2):
        # 2600-01-01 > 2**64 ns
        # os.utime('input/empty', (19880895600, 19880895600))
        # thus, we better test with something not that far in future:
        # 2038-01-19 (1970 + 2^31 - 1 seconds) is the 32bit "deadline":
        os.utime('input/empty', (2**31 - 1, 2**31 - 1))
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('flagfile', size=1024)
        # Directory
        self.create_regular_file('dir2/file2', size=1024 * 80)
        # File mode
        os.chmod('input/file1', 0o4755)
        # Hard link
        if are_hardlinks_supported():
            os.link(os.path.join(self.input_path, 'file1'),
                    os.path.join(self.input_path, 'hardlink'))
        # Symlink
        if are_symlinks_supported():
            os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        self.create_regular_file('fusexattr', size=1)
        if not xattr.XATTR_FAKEROOT and xattr.is_enabled(self.input_path):
            # ironically, due to the way how fakeroot works, comparing fuse file xattrs to orig file xattrs
            # will FAIL if fakeroot supports xattrs, thus we only set the xattr if XATTR_FAKEROOT is False.
            # This is because fakeroot with xattr-support does not propagate xattrs of the underlying file
            # into "fakeroot space". Because the xattrs exposed by borgfs are these of an underlying file
            # (from fakeroots point of view) they are invisible to the test process inside the fakeroot.
            xattr.setxattr(os.path.join(self.input_path, 'fusexattr'), 'user.foo', b'bar')
            # XXX this always fails for me
            # ubuntu 14.04, on a TMP dir filesystem with user_xattr, using fakeroot
            # same for newer ubuntu and centos.
            # if this is supported just on specific platform, platform should be checked first,
            # so that the test setup for all tests using it does not fail here always for others.
            # xattr.setxattr(os.path.join(self.input_path, 'link1'), 'user.foo_symlink', b'bar_symlink', follow_symlinks=False)
        # FIFO node
        if are_fifos_supported():
            os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        if has_lchflags:
            platform.set_flags(os.path.join(self.input_path, 'flagfile'), stat.UF_NODUMP)
        try:
            # Block device
            os.mknod('input/bdev', 0o600 | stat.S_IFBLK, os.makedev(10, 20))
            # Char device
            os.mknod('input/cdev', 0o600 | stat.S_IFCHR, os.makedev(30, 40))
            # File mode
            os.chmod('input/dir2', 0o555)  # if we take away write perms, we need root to remove contents
            # File owner
            os.chown('input/file1', 100, 200)  # raises OSError invalid argument on cygwin
            have_root = True  # we have (fake)root
        except PermissionError:
            have_root = False
        except OSError as e:
            # Note: ENOSYS "Function not implemented" happens as non-root on Win 10 Linux Subsystem.
            if e.errno not in (errno.EINVAL, errno.ENOSYS):
                raise
            have_root = False
        return have_root


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_basic_functionality(self):
        have_root = self.create_test_files()
        # fork required to test show-rc output
        output = self.cmd('init', '--encryption=repokey', '--show-version', '--show-rc', self.repository_location, fork=True)
        self.assert_in('borgbackup version', output)
        self.assert_in('terminating with success status, rc 0', output)
        self.cmd('create', self.repository_location + '::test', 'input')
        output = self.cmd('create', '--stats', self.repository_location + '::test.2', 'input')
        self.assert_in('Archive name: test.2', output)
        self.assert_in('This archive: ', output)
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        list_output = self.cmd('list', '--short', self.repository_location)
        self.assert_in('test', list_output)
        self.assert_in('test.2', list_output)
        expected = [
            'input',
            'input/bdev',
            'input/cdev',
            'input/dir2',
            'input/dir2/file2',
            'input/empty',
            'input/file1',
            'input/flagfile',
        ]
        if are_fifos_supported():
            expected.append('input/fifo1')
        if are_symlinks_supported():
            expected.append('input/link1')
        if are_hardlinks_supported():
            expected.append('input/hardlink')
        if not have_root:
            # we could not create these device files without (fake)root
            expected.remove('input/bdev')
            expected.remove('input/cdev')
        if has_lchflags:
            # remove the file we did not backup, so input and output become equal
            expected.remove('input/flagfile')  # this file is UF_NODUMP
            os.remove(os.path.join('input', 'flagfile'))
        list_output = self.cmd('list', '--short', self.repository_location + '::test')
        for name in expected:
            self.assert_in(name, list_output)
        self.assert_dirs_equal('input', 'output/input')
        info_output = self.cmd('info', self.repository_location + '::test')
        item_count = 4 if has_lchflags else 5  # one file is UF_NODUMP
        self.assert_in('Number of files: %d' % item_count, info_output)
        shutil.rmtree(self.cache_path)
        info_output2 = self.cmd('info', self.repository_location + '::test')

        def filter(output):
            # filter for interesting "info" output, ignore cache rebuilding related stuff
            prefixes = ['Name:', 'Fingerprint:', 'Number of files:', 'This archive:',
                        'All archives:', 'Chunk index:', ]
            result = []
            for line in output.splitlines():
                for prefix in prefixes:
                    if line.startswith(prefix):
                        result.append(line)
            return '\n'.join(result)

        # the interesting parts of info_output2 and info_output should be same
        self.assert_equal(filter(info_output), filter(info_output2))

    def test_unix_socket(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(os.path.join(self.input_path, 'unix-socket'))
        except PermissionError as err:
            if err.errno == errno.EPERM:
                pytest.skip('unix sockets disabled or not supported')
            elif err.errno == errno.EACCES:
                pytest.skip('permission denied to create unix sockets')
        self.cmd('create', self.repository_location + '::test', 'input')
        sock.close()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert not os.path.exists('input/unix-socket')

    @pytest.mark.skipif(not are_symlinks_supported(), reason='symlinks not supported')
    def test_symlink_extract(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert os.readlink('input/link1') == 'somewhere'

    # Search for O_NOATIME there: https://www.gnu.org/software/hurd/contributing.html - we just
    # skip the test on Hurd, it is not critical anyway, just testing a performance optimization.
    @pytest.mark.skipif(sys.platform == 'gnu0', reason="O_NOATIME is strangely broken on GNU Hurd")
    @pytest.mark.skipif(not is_utime_fully_supported(), reason='cannot properly setup and execute test without utime')
    def test_atime(self):
        def has_noatime(some_file):
            atime_before = os.stat(some_file).st_atime_ns
            try:
                with open(os.open(some_file, flags_noatime)) as file:
                    file.read()
            except PermissionError:
                return False
            else:
                atime_after = os.stat(some_file).st_atime_ns
                noatime_used = flags_noatime != flags_normal
                return noatime_used and atime_before == atime_after

        self.create_test_files()
        atime, mtime = 123456780, 234567890
        have_noatime = has_noatime('input/file1')
        os.utime('input/file1', (atime, mtime))
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        sti = os.stat('input/file1')
        sto = os.stat('output/input/file1')
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9
        if have_noatime:
            assert sti.st_atime_ns == sto.st_atime_ns == atime * 1e9
        else:
            # it touched the input file's atime while backing it up
            assert sto.st_atime_ns == atime * 1e9

    def _extract_repository_id(self, path):
        with Repository(self.repository_path) as repository:
            return repository.id

    def _set_repository_id(self, path, id):
        config = ConfigParser(interpolation=None)
        config.read(os.path.join(path, 'config'))
        config.set('repository', 'id', bin_to_hex(id))
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)
        with Repository(self.repository_path) as repository:
            return repository.id

    def test_sparse_file(self):
        def is_sparse(fn, total_size, hole_size):
            st = os.stat(fn)
            assert st.st_size == total_size
            sparse = True
            if sparse and hasattr(st, 'st_blocks') and st.st_blocks * 512 >= st.st_size:
                sparse = False
            if sparse and hasattr(os, 'SEEK_HOLE') and hasattr(os, 'SEEK_DATA'):
                with open(fn, 'rb') as fd:
                    # only check if the first hole is as expected, because the 2nd hole check
                    # is problematic on xfs due to its "dynamic speculative EOF preallocation
                    try:
                        if fd.seek(0, os.SEEK_HOLE) != 0:
                            sparse = False
                        if fd.seek(0, os.SEEK_DATA) != hole_size:
                            sparse = False
                    except OSError:
                        # OS/FS does not really support SEEK_HOLE/SEEK_DATA
                        sparse = False
            return sparse

        filename = os.path.join(self.input_path, 'sparse')
        content = b'foobar'
        hole_size = 5 * (1 << CHUNK_MAX_EXP)  # 5 full chunker buffers
        total_size = hole_size + len(content) + hole_size
        with open(filename, 'wb') as fd:
            # create a file that has a hole at the beginning and end (if the
            # OS and filesystem supports sparse files)
            fd.seek(hole_size, 1)
            fd.write(content)
            fd.seek(hole_size, 1)
            pos = fd.tell()
            fd.truncate(pos)
        # we first check if we could create a sparse input file:
        sparse_support = is_sparse(filename, total_size, hole_size)
        if sparse_support:
            # we could create a sparse input file, so creating a backup of it and
            # extracting it again (as sparse) should also work:
            self.cmd('init', '--encryption=repokey', self.repository_location)
            self.cmd('create', self.repository_location + '::test', 'input')
            with changedir(self.output_path):
                self.cmd('extract', '--sparse', self.repository_location + '::test')
            self.assert_dirs_equal('input', 'output/input')
            filename = os.path.join(self.output_path, 'input', 'sparse')
            with open(filename, 'rb') as fd:
                # check if file contents are as expected
                self.assert_equal(fd.read(hole_size), b'\0' * hole_size)
                self.assert_equal(fd.read(len(content)), content)
                self.assert_equal(fd.read(hole_size), b'\0' * hole_size)
            self.assert_true(is_sparse(filename, total_size, hole_size))

    def test_unusual_filenames(self):
        filenames = ['normal', 'with some blanks', '(with_parens)', ]
        for filename in filenames:
            filename = os.path.join(self.input_path, filename)
            with open(filename, 'wb'):
                pass
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        for filename in filenames:
            with changedir('output'):
                self.cmd('extract', self.repository_location + '::test', os.path.join('input', filename))
            assert os.path.exists(os.path.join('output', 'input', filename))

    def test_repository_swap_detection(self):
        self.create_test_files()
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd('create', self.repository_location + '::test', 'input')
        shutil.rmtree(self.repository_path)
        self.cmd('init', '--encryption=none', self.repository_location)
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        if self.FORK_DEFAULT:
            self.cmd('create', self.repository_location + '::test.2', 'input', exit_code=EXIT_ERROR)
        else:
            self.assert_raises(Cache.EncryptionMethodMismatch, lambda: self.cmd('create', self.repository_location + '::test.2', 'input'))

    def test_repository_swap_detection2(self):
        self.create_test_files()
        self.cmd('init', '--encryption=none', self.repository_location + '_unencrypted')
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        self.cmd('init', '--encryption=repokey', self.repository_location + '_encrypted')
        self.cmd('create', self.repository_location + '_encrypted::test', 'input')
        shutil.rmtree(self.repository_path + '_encrypted')
        os.rename(self.repository_path + '_unencrypted', self.repository_path + '_encrypted')
        if self.FORK_DEFAULT:
            self.cmd('create', self.repository_location + '_encrypted::test.2', 'input', exit_code=EXIT_ERROR)
        else:
            self.assert_raises(Cache.RepositoryAccessAborted, lambda: self.cmd('create', self.repository_location + '_encrypted::test.2', 'input'))

    def test_repository_swap_detection_no_cache(self):
        self.create_test_files()
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd('create', self.repository_location + '::test', 'input')
        shutil.rmtree(self.repository_path)
        self.cmd('init', '--encryption=none', self.repository_location)
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        self.cmd('delete', '--cache-only', self.repository_location)
        if self.FORK_DEFAULT:
            self.cmd('create', self.repository_location + '::test.2', 'input', exit_code=EXIT_ERROR)
        else:
            self.assert_raises(Cache.EncryptionMethodMismatch, lambda: self.cmd('create', self.repository_location + '::test.2', 'input'))

    def test_repository_swap_detection2_no_cache(self):
        self.create_test_files()
        self.cmd('init', '--encryption=none', self.repository_location + '_unencrypted')
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        self.cmd('init', '--encryption=repokey', self.repository_location + '_encrypted')
        self.cmd('create', self.repository_location + '_encrypted::test', 'input')
        self.cmd('delete', '--cache-only', self.repository_location + '_unencrypted')
        self.cmd('delete', '--cache-only', self.repository_location + '_encrypted')
        shutil.rmtree(self.repository_path + '_encrypted')
        os.rename(self.repository_path + '_unencrypted', self.repository_path + '_encrypted')
        if self.FORK_DEFAULT:
            self.cmd('create', self.repository_location + '_encrypted::test.2', 'input', exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd('create', self.repository_location + '_encrypted::test.2', 'input')

    def test_repository_move(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
        os.rename(self.repository_path, self.repository_path + '_new')
        with environment_variable(BORG_RELOCATED_REPO_ACCESS_IS_OK='yes'):
            self.cmd('info', self.repository_location + '_new')
        security_dir = get_security_dir(repository_id)
        with open(os.path.join(security_dir, 'location')) as fd:
            location = fd.read()
            assert location == Location(self.repository_location + '_new').canonical_path()
        # Needs no confirmation anymore
        self.cmd('info', self.repository_location + '_new')
        shutil.rmtree(self.cache_path)
        self.cmd('info', self.repository_location + '_new')
        shutil.rmtree(security_dir)
        self.cmd('info', self.repository_location + '_new')
        for file in ('location', 'key-type', 'manifest-timestamp'):
            assert os.path.exists(os.path.join(security_dir, file))

    def test_security_dir_compat(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
        security_dir = get_security_dir(repository_id)
        with open(os.path.join(security_dir, 'location'), 'w') as fd:
            fd.write('something outdated')
        # This is fine, because the cache still has the correct information. security_dir and cache can disagree
        # if older versions are used to confirm a renamed repository.
        self.cmd('info', self.repository_location)

    def test_unknown_unencrypted(self):
        self.cmd('init', '--encryption=none', self.repository_location)
        repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
        security_dir = get_security_dir(repository_id)
        # Ok: repository is known
        self.cmd('info', self.repository_location)

        # Ok: repository is still known (through security_dir)
        shutil.rmtree(self.cache_path)
        self.cmd('info', self.repository_location)

        # Needs confirmation: cache and security dir both gone (eg. another host or rm -rf ~)
        shutil.rmtree(self.cache_path)
        shutil.rmtree(security_dir)
        if self.FORK_DEFAULT:
            self.cmd('info', self.repository_location, exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.CacheInitAbortedError):
                self.cmd('info', self.repository_location)
        with environment_variable(BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK='yes'):
            self.cmd('info', self.repository_location)

    def test_strip_components(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('dir/file')
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', '--strip-components', '3')
            self.assert_true(not os.path.exists('file'))
            with self.assert_creates_file('file'):
                self.cmd('extract', self.repository_location + '::test', '--strip-components', '2')
            with self.assert_creates_file('dir/file'):
                self.cmd('extract', self.repository_location + '::test', '--strip-components', '1')
            with self.assert_creates_file('input/dir/file'):
                self.cmd('extract', self.repository_location + '::test', '--strip-components', '0')

    def _extract_hardlinks_setup(self):
        os.mkdir(os.path.join(self.input_path, 'dir1'))
        os.mkdir(os.path.join(self.input_path, 'dir1/subdir'))

        self.create_regular_file('source')
        os.link(os.path.join(self.input_path, 'source'),
                os.path.join(self.input_path, 'abba'))
        os.link(os.path.join(self.input_path, 'source'),
                os.path.join(self.input_path, 'dir1/hardlink'))
        os.link(os.path.join(self.input_path, 'source'),
                os.path.join(self.input_path, 'dir1/subdir/hardlink'))

        self.create_regular_file('dir1/source2')
        os.link(os.path.join(self.input_path, 'dir1/source2'),
                os.path.join(self.input_path, 'dir1/aaaa'))

        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')

    @pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
    def test_strip_components_links(self):
        self._extract_hardlinks_setup()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', '--strip-components', '2')
            assert os.stat('hardlink').st_nlink == 2
            assert os.stat('subdir/hardlink').st_nlink == 2
            assert os.stat('aaaa').st_nlink == 2
            assert os.stat('source2').st_nlink == 2
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert os.stat('input/dir1/hardlink').st_nlink == 4

    @pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
    def test_extract_hardlinks(self):
        self._extract_hardlinks_setup()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', 'input/dir1')
            assert os.stat('input/dir1/hardlink').st_nlink == 2
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 2
            assert os.stat('input/dir1/aaaa').st_nlink == 2
            assert os.stat('input/dir1/source2').st_nlink == 2
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert os.stat('input/dir1/hardlink').st_nlink == 4

    def test_extract_include_exclude(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file3', size=1024 * 80)
        self.create_regular_file('file4', size=1024 * 80)
        self.cmd('create', '--exclude=input/file4', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', 'input/file1', )
        self.assert_equal(sorted(os.listdir('output/input')), ['file1'])
        with changedir('output'):
            self.cmd('extract', '--exclude=input/file2', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])
        with changedir('output'):
            self.cmd('extract', '--exclude-from=' + self.exclude_file_path, self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])

    def test_extract_include_exclude_regex(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file3', size=1024 * 80)
        self.create_regular_file('file4', size=1024 * 80)
        self.create_regular_file('file333', size=1024 * 80)

        # Create with regular expression exclusion for file4
        self.cmd('create', '--exclude=re:input/file4$', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file2', 'file3', 'file333'])
        shutil.rmtree('output/input')

        # Extract with regular expression exclusion
        with changedir('output'):
            self.cmd('extract', '--exclude=re:file3+', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file2'])
        shutil.rmtree('output/input')

        # Combine --exclude with fnmatch and regular expression
        with changedir('output'):
            self.cmd('extract', '--exclude=input/file2', '--exclude=re:file[01]', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file3', 'file333'])
        shutil.rmtree('output/input')

        # Combine --exclude-from and regular expression exclusion
        with changedir('output'):
            self.cmd('extract', '--exclude-from=' + self.exclude_file_path, '--exclude=re:file1',
                     '--exclude=re:file(\\d)\\1\\1$', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file3'])

    def test_extract_include_exclude_regex_from_file(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file3', size=1024 * 80)
        self.create_regular_file('file4', size=1024 * 80)
        self.create_regular_file('file333', size=1024 * 80)
        self.create_regular_file('aa:something', size=1024 * 80)

        # Create while excluding using mixed pattern styles
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b're:input/file4$\n')
            fd.write(b'fm:*aa:*thing\n')

        self.cmd('create', '--exclude-from=' + self.exclude_file_path, self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file2', 'file3', 'file333'])
        shutil.rmtree('output/input')

        # Exclude using regular expression
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b're:file3+\n')

        with changedir('output'):
            self.cmd('extract', '--exclude-from=' + self.exclude_file_path, self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file2'])
        shutil.rmtree('output/input')

        # Mixed exclude pattern styles
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b're:file(\\d)\\1\\1$\n')
            fd.write(b'fm:nothingwillmatchthis\n')
            fd.write(b'*/file1\n')
            fd.write(b're:file2$\n')

        with changedir('output'):
            self.cmd('extract', '--exclude-from=' + self.exclude_file_path, self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file3'])

    def test_extract_with_pattern(self):
        self.cmd("init", '--encryption=repokey', self.repository_location)
        self.create_regular_file("file1", size=1024 * 80)
        self.create_regular_file("file2", size=1024 * 80)
        self.create_regular_file("file3", size=1024 * 80)
        self.create_regular_file("file4", size=1024 * 80)
        self.create_regular_file("file333", size=1024 * 80)

        self.cmd("create", self.repository_location + "::test", "input")

        # Extract everything with regular expression
        with changedir("output"):
            self.cmd("extract", self.repository_location + "::test", "re:.*")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file3", "file333", "file4"])
        shutil.rmtree("output/input")

        # Extract with pattern while also excluding files
        with changedir("output"):
            self.cmd("extract", "--exclude=re:file[34]$", self.repository_location + "::test", r"re:file\d$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2"])
        shutil.rmtree("output/input")

        # Combine --exclude with pattern for extraction
        with changedir("output"):
            self.cmd("extract", "--exclude=input/file1", self.repository_location + "::test", "re:file[12]$")
        self.assert_equal(sorted(os.listdir("output/input")), ["file2"])
        shutil.rmtree("output/input")

        # Multiple pattern
        with changedir("output"):
            self.cmd("extract", self.repository_location + "::test", "fm:input/file1", "fm:*file33*", "input/file2")
        self.assert_equal(sorted(os.listdir("output/input")), ["file1", "file2", "file333"])

    def test_extract_list_output(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file', size=1024 * 80)

        self.cmd('create', self.repository_location + '::test', 'input')

        with changedir('output'):
            output = self.cmd('extract', self.repository_location + '::test')
        self.assert_not_in("input/file", output)
        shutil.rmtree('output/input')

        with changedir('output'):
            output = self.cmd('extract', '--info', self.repository_location + '::test')
        self.assert_not_in("input/file", output)
        shutil.rmtree('output/input')

        with changedir('output'):
            output = self.cmd('extract', '--list', self.repository_location + '::test')
        self.assert_in("input/file", output)
        shutil.rmtree('output/input')

        with changedir('output'):
            output = self.cmd('extract', '--list', '--info', self.repository_location + '::test')
        self.assert_in("input/file", output)

    def test_extract_progress(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file', size=1024 * 80)
        self.cmd('create', self.repository_location + '::test', 'input')

        with changedir('output'):
            output = self.cmd('extract', self.repository_location + '::test', '--progress')
            assert 'Extracting:' in output

    def _create_test_caches(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('cache1/%s' % CACHE_TAG_NAME,
                                 contents=CACHE_TAG_CONTENTS + b' extra stuff')
        self.create_regular_file('cache2/%s' % CACHE_TAG_NAME,
                                 contents=b'invalid signature')
        os.mkdir('input/cache3')
        os.link('input/cache1/%s' % CACHE_TAG_NAME, 'input/cache3/%s' % CACHE_TAG_NAME)

    def _assert_test_caches(self):
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['cache2', 'file1'])
        self.assert_equal(sorted(os.listdir('output/input/cache2')), [CACHE_TAG_NAME])

    def test_exclude_caches(self):
        self._create_test_caches()
        self.cmd('create', '--exclude-caches', self.repository_location + '::test', 'input')
        self._assert_test_caches()

    def test_recreate_exclude_caches(self):
        self._create_test_caches()
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('recreate', '--exclude-caches', self.repository_location + '::test')
        self._assert_test_caches()

    def _create_test_tagged(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('tagged1/.NOBACKUP')
        self.create_regular_file('tagged2/00-NOBACKUP')
        self.create_regular_file('tagged3/.NOBACKUP/file2')

    def _assert_test_tagged(self):
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'tagged3'])

    def test_exclude_tagged(self):
        self._create_test_tagged()
        self.cmd('create', '--exclude-if-present', '.NOBACKUP', '--exclude-if-present', '00-NOBACKUP', self.repository_location + '::test', 'input')
        self._assert_test_tagged()

    def test_recreate_exclude_tagged(self):
        self._create_test_tagged()
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('recreate', '--exclude-if-present', '.NOBACKUP', '--exclude-if-present', '00-NOBACKUP',
                 self.repository_location + '::test')
        self._assert_test_tagged()

    def _create_test_keep_tagged(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file0', size=1024)
        self.create_regular_file('tagged1/.NOBACKUP1')
        self.create_regular_file('tagged1/file1', size=1024)
        self.create_regular_file('tagged2/.NOBACKUP2')
        self.create_regular_file('tagged2/file2', size=1024)
        self.create_regular_file('tagged3/%s' % CACHE_TAG_NAME,
                                 contents=CACHE_TAG_CONTENTS + b' extra stuff')
        self.create_regular_file('tagged3/file3', size=1024)
        self.create_regular_file('taggedall/.NOBACKUP1')
        self.create_regular_file('taggedall/.NOBACKUP2')
        self.create_regular_file('taggedall/%s' % CACHE_TAG_NAME,
                                 contents=CACHE_TAG_CONTENTS + b' extra stuff')
        self.create_regular_file('taggedall/file4', size=1024)

    def _assert_test_keep_tagged(self):
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file0', 'tagged1', 'tagged2', 'tagged3', 'taggedall'])
        self.assert_equal(os.listdir('output/input/tagged1'), ['.NOBACKUP1'])
        self.assert_equal(os.listdir('output/input/tagged2'), ['.NOBACKUP2'])
        self.assert_equal(os.listdir('output/input/tagged3'), [CACHE_TAG_NAME])
        self.assert_equal(sorted(os.listdir('output/input/taggedall')),
                          ['.NOBACKUP1', '.NOBACKUP2', CACHE_TAG_NAME, ])

    def test_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd('create', '--exclude-if-present', '.NOBACKUP1', '--exclude-if-present', '.NOBACKUP2',
                 '--exclude-caches', '--keep-tag-files', self.repository_location + '::test', 'input')
        self._assert_test_keep_tagged()

    def test_recreate_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('recreate', '--exclude-if-present', '.NOBACKUP1', '--exclude-if-present', '.NOBACKUP2',
                 '--exclude-caches', '--keep-tag-files', self.repository_location + '::test')
        self._assert_test_keep_tagged()

    @pytest.mark.skipif(not xattr.XATTR_FAKEROOT, reason='Linux capabilities test, requires fakeroot >= 1.20.2')
    def test_extract_capabilities(self):
        fchown = os.fchown

        # We need to manually patch chown to get the behaviour Linux has, since fakeroot does not
        # accurately model the interaction of chown(2) and Linux capabilities, i.e. it does not remove them.
        def patched_fchown(fd, uid, gid):
            xattr.setxattr(fd, 'security.capability', None, follow_symlinks=False)
            fchown(fd, uid, gid)

        # The capability descriptor used here is valid and taken from a /usr/bin/ping
        capabilities = b'\x01\x00\x00\x02\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.create_regular_file('file')
        xattr.setxattr('input/file', 'security.capability', capabilities)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            with patch.object(os, 'fchown', patched_fchown):
                self.cmd('extract', self.repository_location + '::test')
            assert xattr.getxattr('input/file', 'security.capability') == capabilities

    def test_path_normalization(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('dir1/dir2/file', size=1024 * 80)
        with changedir('input/dir1/dir2'):
            self.cmd('create', self.repository_location + '::test', '../../../input/dir1/../dir1/dir2/..')
        output = self.cmd('list', self.repository_location + '::test')
        self.assert_not_in('..', output)
        self.assert_in(' input/dir1/dir2/file', output)

    def test_exclude_normalization(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        with changedir('input'):
            self.cmd('create', '--exclude=file1', self.repository_location + '::test1', '.')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test1')
        self.assert_equal(sorted(os.listdir('output')), ['file2'])
        with changedir('input'):
            self.cmd('create', '--exclude=./file1', self.repository_location + '::test2', '.')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test2')
        self.assert_equal(sorted(os.listdir('output')), ['file2'])
        self.cmd('create', '--exclude=input/./file1', self.repository_location + '::test3', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test3')
        self.assert_equal(sorted(os.listdir('output/input')), ['file2'])

    def test_repeated_files(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', 'input')

    def test_overwrite(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        # Overwriting regular files and directories should be supported
        os.mkdir('output/input')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/dir2')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_dirs_equal('input', 'output/input')
        # But non-empty dirs should fail
        os.unlink('output/input/file1')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/file1/dir')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', exit_code=1)

    def test_rename(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', self.repository_location + '::test.2', 'input')
        self.cmd('extract', '--dry-run', self.repository_location + '::test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        self.cmd('rename', self.repository_location + '::test', 'test.3')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        self.cmd('rename', self.repository_location + '::test.2', 'test.4')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.3')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.4')
        # Make sure both archives have been renamed
        with Repository(self.repository_path) as repository:
            manifest, key = Manifest.load(repository)
        self.assert_equal(len(manifest.archives), 2)
        self.assert_in('test.3', manifest.archives)
        self.assert_in('test.4', manifest.archives)

    def test_info(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        info_repo = self.cmd('info', self.repository_location)
        assert 'All archives:' in info_repo
        info_archive = self.cmd('info', self.repository_location + '::test')
        assert 'Archive name: test\n' in info_archive
        info_archive = self.cmd('info', '--first', '1', self.repository_location)
        assert 'Archive name: test\n' in info_archive

    def test_comment(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', 'input')
        self.cmd('create', '--comment', 'this is the comment', self.repository_location + '::test2', 'input')
        self.cmd('create', '--comment', '"deleted" comment', self.repository_location + '::test3', 'input')
        self.cmd('create', '--comment', 'preserved comment', self.repository_location + '::test4', 'input')
        assert 'Comment: \n' in self.cmd('info', self.repository_location + '::test1')
        assert 'Comment: this is the comment' in self.cmd('info', self.repository_location + '::test2')

        self.cmd('recreate', self.repository_location + '::test1', '--comment', 'added comment')
        self.cmd('recreate', self.repository_location + '::test2', '--comment', 'modified comment')
        self.cmd('recreate', self.repository_location + '::test3', '--comment', '')
        self.cmd('recreate', self.repository_location + '::test4', '12345')
        assert 'Comment: added comment' in self.cmd('info', self.repository_location + '::test1')
        assert 'Comment: modified comment' in self.cmd('info', self.repository_location + '::test2')
        assert 'Comment: \n' in self.cmd('info', self.repository_location + '::test3')
        assert 'Comment: preserved comment' in self.cmd('info', self.repository_location + '::test4')

    def test_delete(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', self.repository_location + '::test.2', 'input')
        self.cmd('create', self.repository_location + '::test.3', 'input')
        self.cmd('create', self.repository_location + '::another_test.1', 'input')
        self.cmd('create', self.repository_location + '::another_test.2', 'input')
        self.cmd('extract', '--dry-run', self.repository_location + '::test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        self.cmd('delete', '--prefix', 'another_', self.repository_location)
        self.cmd('delete', '--last', '1', self.repository_location)
        self.cmd('delete', self.repository_location + '::test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        output = self.cmd('delete', '--stats', self.repository_location + '::test.2')
        self.assert_in('Deleted data:', output)
        # Make sure all data except the manifest has been deleted
        with Repository(self.repository_path) as repository:
            self.assert_equal(len(repository), 1)

    def test_delete_repo(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', self.repository_location + '::test.2', 'input')
        os.environ['BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'] = 'no'
        self.cmd('delete', self.repository_location, exit_code=2)
        assert os.path.exists(self.repository_path)
        os.environ['BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
        self.cmd('delete', self.repository_location)
        # Make sure the repo is gone
        self.assertFalse(os.path.exists(self.repository_path))

    def test_corrupted_repository(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test')
        output = self.cmd('check', '--show-version', self.repository_location)
        self.assert_in('borgbackup version', output)  # implied output even without --info given
        self.assert_not_in('Starting repository check', output)  # --info not given for root logger

        name = sorted(os.listdir(os.path.join(self.tmpdir, 'repository', 'data', '0')), reverse=True)[1]
        with open(os.path.join(self.tmpdir, 'repository', 'data', '0', name), 'r+b') as fd:
            fd.seek(100)
            fd.write(b'XXXX')
        output = self.cmd('check', '--info', self.repository_location, exit_code=1)
        self.assert_in('Starting repository check', output)  # --info given for root logger

    # we currently need to be able to create a lock directory inside the repo:
    @pytest.mark.xfail(reason="we need to be able to create the lock directory inside the repo")
    def test_readonly_repository(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        os.system('chmod -R ugo-w ' + self.repository_path)
        try:
            self.cmd('extract', '--dry-run', self.repository_location + '::test')
        finally:
            # Restore permissions so shutil.rmtree is able to delete it
            os.system('chmod -R u+w ' + self.repository_path)

    @pytest.mark.skipif('BORG_TESTS_IGNORE_MODES' in os.environ, reason='modes unreliable')
    def test_umask(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        mode = os.stat(self.repository_path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_create_dry_run(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', '--dry-run', self.repository_location + '::test', 'input')
        # Make sure no archive has been created
        with Repository(self.repository_path) as repository:
            manifest, key = Manifest.load(repository)
        self.assert_equal(len(manifest.archives), 0)

    def test_progress_on(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--progress', self.repository_location + '::test4', 'input')
        self.assert_in("\r", output)

    def test_progress_off(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', self.repository_location + '::test5', 'input')
        self.assert_not_in("\r", output)

    def test_file_status(self):
        """test that various file status show expected results

        clearly incomplete: only tests for the weird "unchanged" status for now"""
        now = time.time()
        self.create_regular_file('file1', size=1024 * 80)
        os.utime('input/file1', (now - 5, now - 5))  # 5 seconds ago
        self.create_regular_file('file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', self.repository_location + '::test', 'input')
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        # should find first file as unmodified
        output = self.cmd('create', '--list', self.repository_location + '::test1', 'input')
        self.assert_in("U input/file1", output)
        # this is expected, although surprising, for why, see:
        # https://borgbackup.readthedocs.org/en/latest/faq.html#i-am-seeing-a-added-status-for-a-unchanged-file
        self.assert_in("A input/file2", output)

    def test_file_status_excluded(self):
        """test that excluded paths are listed"""

        now = time.time()
        self.create_regular_file('file1', size=1024 * 80)
        os.utime('input/file1', (now - 5, now - 5))  # 5 seconds ago
        self.create_regular_file('file2', size=1024 * 80)
        if has_lchflags:
            self.create_regular_file('file3', size=1024 * 80)
            platform.set_flags(os.path.join(self.input_path, 'file3'), stat.UF_NODUMP)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', self.repository_location + '::test', 'input')
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)
        # should find second file as excluded
        output = self.cmd('create', '--list', self.repository_location + '::test1', 'input', '--exclude', '*/file2')
        self.assert_in("U input/file1", output)
        self.assert_in("x input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)

    def test_create_topical(self):
        now = time.time()
        self.create_regular_file('file1', size=1024 * 80)
        os.utime('input/file1', (now-5, now-5))
        self.create_regular_file('file2', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        # no listing by default
        output = self.cmd('create', self.repository_location + '::test', 'input')
        self.assert_not_in('file1', output)
        # shouldn't be listed even if unchanged
        output = self.cmd('create', self.repository_location + '::test0', 'input')
        self.assert_not_in('file1', output)
        # should list the file as unchanged
        output = self.cmd('create', '--list', '--filter=U', self.repository_location + '::test1', 'input')
        self.assert_in('file1', output)
        # should *not* list the file as changed
        output = self.cmd('create', '--list', '--filter=AM', self.repository_location + '::test2', 'input')
        self.assert_not_in('file1', output)
        # change the file
        self.create_regular_file('file1', size=1024 * 100)
        # should list the file as changed
        output = self.cmd('create', '--list', '--filter=AM', self.repository_location + '::test3', 'input')
        self.assert_in('file1', output)

    def test_create_read_special_broken_symlink(self):
        os.symlink('somewhere doesnt exist', os.path.join(self.input_path, 'link'))
        self.cmd('init', '--encryption=repokey', self.repository_location)
        archive = self.repository_location + '::test'
        self.cmd('create', '--read-special', archive, 'input')
        output = self.cmd('list', archive)
        assert 'input/link -> somewhere doesnt exist' in output

    # def test_cmdline_compatibility(self):
    #    self.create_regular_file('file1', size=1024 * 80)
    #    self.cmd('init', '--encryption=repokey', self.repository_location)
    #    self.cmd('create', self.repository_location + '::test', 'input')
    #    output = self.cmd('foo', self.repository_location, '--old')
    #    self.assert_in('"--old" has been deprecated. Use "--new" instead', output)

    def test_prune_repository(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', src_dir)
        self.cmd('create', self.repository_location + '::test2', src_dir)
        # these are not really a checkpoints, but they look like some:
        self.cmd('create', self.repository_location + '::test3.checkpoint', src_dir)
        self.cmd('create', self.repository_location + '::test3.checkpoint.1', src_dir)
        self.cmd('create', self.repository_location + '::test4.checkpoint', src_dir)
        output = self.cmd('prune', '--list', '--dry-run', self.repository_location, '--keep-daily=2')
        self.assert_in('Keeping archive: test2', output)
        self.assert_in('Would prune:     test1', output)
        # must keep the latest non-checkpoint archive:
        self.assert_in('Keeping archive: test2', output)
        # must keep the latest checkpoint archive:
        self.assert_in('Keeping archive: test4.checkpoint', output)
        output = self.cmd('list', self.repository_location)
        self.assert_in('test1', output)
        self.assert_in('test2', output)
        self.assert_in('test3.checkpoint', output)
        self.assert_in('test3.checkpoint.1', output)
        self.assert_in('test4.checkpoint', output)
        self.cmd('prune', self.repository_location, '--keep-daily=2')
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('test1', output)
        # the latest non-checkpoint archive must be still there:
        self.assert_in('test2', output)
        # only the latest checkpoint archive must still be there:
        self.assert_not_in('test3.checkpoint', output)
        self.assert_not_in('test3.checkpoint.1', output)
        self.assert_in('test4.checkpoint', output)
        # now we supercede the latest checkpoint by a successful backup:
        self.cmd('create', self.repository_location + '::test5', src_dir)
        self.cmd('prune', self.repository_location, '--keep-daily=2')
        output = self.cmd('list', self.repository_location)
        # all checkpoints should be gone now:
        self.assert_not_in('checkpoint', output)
        # the latest archive must be still there
        self.assert_in('test5', output)

    def test_prune_repository_save_space(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', src_dir)
        self.cmd('create', self.repository_location + '::test2', src_dir)
        output = self.cmd('prune', '--list', '--stats', '--dry-run', self.repository_location, '--keep-daily=2')
        self.assert_in('Keeping archive: test2', output)
        self.assert_in('Would prune:     test1', output)
        self.assert_in('Deleted data:', output)
        output = self.cmd('list', self.repository_location)
        self.assert_in('test1', output)
        self.assert_in('test2', output)
        self.cmd('prune', '--save-space', self.repository_location, '--keep-daily=2')
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('test1', output)
        self.assert_in('test2', output)

    def test_prune_repository_prefix(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::foo-2015-08-12-10:00', src_dir)
        self.cmd('create', self.repository_location + '::foo-2015-08-12-20:00', src_dir)
        self.cmd('create', self.repository_location + '::bar-2015-08-12-10:00', src_dir)
        self.cmd('create', self.repository_location + '::bar-2015-08-12-20:00', src_dir)
        output = self.cmd('prune', '--list', '--dry-run', self.repository_location, '--keep-daily=2', '--prefix=foo-')
        self.assert_in('Keeping archive: foo-2015-08-12-20:00', output)
        self.assert_in('Would prune:     foo-2015-08-12-10:00', output)
        output = self.cmd('list', self.repository_location)
        self.assert_in('foo-2015-08-12-10:00', output)
        self.assert_in('foo-2015-08-12-20:00', output)
        self.assert_in('bar-2015-08-12-10:00', output)
        self.assert_in('bar-2015-08-12-20:00', output)
        self.cmd('prune', self.repository_location, '--keep-daily=2', '--prefix=foo-')
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('foo-2015-08-12-10:00', output)
        self.assert_in('foo-2015-08-12-20:00', output)
        self.assert_in('bar-2015-08-12-10:00', output)
        self.assert_in('bar-2015-08-12-20:00', output)

    def test_list_prefix(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test-1', src_dir)
        self.cmd('create', self.repository_location + '::something-else-than-test-1', src_dir)
        self.cmd('create', self.repository_location + '::test-2', src_dir)
        output = self.cmd('list', '--prefix=test-', self.repository_location)
        self.assert_in('test-1', output)
        self.assert_in('test-2', output)
        self.assert_not_in('something-else', output)

    def test_list_format(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        test_archive = self.repository_location + '::test'
        self.cmd('create', test_archive, src_dir)
        output_warn = self.cmd('list', '--list-format', '-', test_archive)
        self.assert_in('--list-format" has been deprecated.', output_warn)
        output_1 = self.cmd('list', test_archive)
        output_2 = self.cmd('list', '--format', '{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}', test_archive)
        output_3 = self.cmd('list', '--format', '{mtime:%s} {path}{NL}', test_archive)
        self.assertEqual(output_1, output_2)
        self.assertNotEqual(output_1, output_3)

    def test_list_repository_format(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test-1', src_dir)
        self.cmd('create', self.repository_location + '::test-2', src_dir)
        output_1 = self.cmd('list', self.repository_location)
        output_2 = self.cmd('list', '--format', '{archive:<36} {time} [{id}]{NL}', self.repository_location)
        self.assertEqual(output_1, output_2)
        output_1 = self.cmd('list', '--short', self.repository_location)
        self.assertEqual(output_1, 'test-1\ntest-2\n')
        output_1 = self.cmd('list', '--format', '{barchive}/', self.repository_location)
        self.assertEqual(output_1, 'test-1/test-2/')

    def test_list_hash(self):
        self.create_regular_file('empty_file', size=0)
        self.create_regular_file('amb', contents=b'a' * 1000000)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        test_archive = self.repository_location + '::test'
        self.cmd('create', test_archive, 'input')
        output = self.cmd('list', '--format', '{sha256} {path}{NL}', test_archive)
        assert "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0 input/amb" in output
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 input/empty_file" in output

    def test_list_chunk_counts(self):
        self.create_regular_file('empty_file', size=0)
        self.create_regular_file('two_chunks')
        with open(os.path.join(self.input_path, 'two_chunks'), 'wb') as fd:
            fd.write(b'abba' * 2000000)
            fd.write(b'baab' * 2000000)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        test_archive = self.repository_location + '::test'
        self.cmd('create', test_archive, 'input')
        output = self.cmd('list', '--format', '{num_chunks} {unique_chunks} {path}{NL}', test_archive)
        assert "0 0 input/empty_file" in output
        assert "2 2 input/two_chunks" in output

    def test_list_size(self):
        self.create_regular_file('compressible_file', size=10000)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        test_archive = self.repository_location + '::test'
        self.cmd('create', '-C', 'lz4', test_archive, 'input')
        output = self.cmd('list', '--format', '{size} {csize} {path}{NL}', test_archive)
        size, csize, path = output.split("\n")[1].split(" ")
        assert int(csize) < int(size)

    def _get_sizes(self, compression, compressible, size=10000):
        if compressible:
            contents = b'X' * size
        else:
            contents = os.urandom(size)
        self.create_regular_file('file', contents=contents)
        self.cmd('init', '--encryption=none', self.repository_location)
        archive = self.repository_location + '::test'
        self.cmd('create', '-C', compression, archive, 'input')
        output = self.cmd('list', '--format', '{size} {csize} {path}{NL}', archive)
        size, csize, path = output.split("\n")[1].split(" ")
        return int(size), int(csize)

    def test_compression_none_compressible(self):
        size, csize = self._get_sizes('none', compressible=True)
        assert csize >= size
        assert csize == size + 3

    def test_compression_none_uncompressible(self):
        size, csize = self._get_sizes('none', compressible=False)
        assert csize >= size
        assert csize == size + 3

    def test_compression_zlib_compressible(self):
        size, csize = self._get_sizes('zlib', compressible=True)
        assert csize < size * 0.1
        assert csize == 35

    def test_compression_zlib_uncompressible(self):
        size, csize = self._get_sizes('zlib', compressible=False)
        assert csize >= size

    def test_compression_auto_compressible(self):
        size, csize = self._get_sizes('auto,zlib', compressible=True)
        assert csize < size * 0.1
        assert csize == 35  # same as compression 'zlib'

    def test_compression_auto_uncompressible(self):
        size, csize = self._get_sizes('auto,zlib', compressible=False)
        assert csize >= size
        assert csize == size + 3  # same as compression 'none'

    def test_compression_lz4_compressible(self):
        size, csize = self._get_sizes('lz4', compressible=True)
        assert csize < size * 0.1

    def test_compression_lz4_uncompressible(self):
        size, csize = self._get_sizes('lz4', compressible=False)
        assert csize >= size

    def test_compression_lzma_compressible(self):
        size, csize = self._get_sizes('lzma', compressible=True)
        assert csize < size * 0.1

    def test_compression_lzma_uncompressible(self):
        size, csize = self._get_sizes('lzma', compressible=False)
        assert csize >= size

    def test_change_passphrase(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        os.environ['BORG_NEW_PASSPHRASE'] = 'newpassphrase'
        # here we have both BORG_PASSPHRASE and BORG_NEW_PASSPHRASE set:
        self.cmd('change-passphrase', self.repository_location)
        os.environ['BORG_PASSPHRASE'] = 'newpassphrase'
        self.cmd('list', self.repository_location)

    def test_break_lock(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('break-lock', self.repository_location)

    def test_usage(self):
        if self.FORK_DEFAULT:
            self.cmd(exit_code=0)
            self.cmd('-h', exit_code=0)
        else:
            self.assert_raises(SystemExit, lambda: self.cmd())
            self.assert_raises(SystemExit, lambda: self.cmd('-h'))

    def test_help(self):
        assert 'Borg' in self.cmd('help')
        assert 'patterns' in self.cmd('help', 'patterns')
        assert 'Initialize' in self.cmd('help', 'init')
        assert 'positional arguments' not in self.cmd('help', 'init', '--epilog-only')
        assert 'This command initializes' not in self.cmd('help', 'init', '--usage-only')

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse(self):
        def has_noatime(some_file):
            atime_before = os.stat(some_file).st_atime_ns
            try:
                os.close(os.open(some_file, flags_noatime))
            except PermissionError:
                return False
            else:
                atime_after = os.stat(some_file).st_atime_ns
                noatime_used = flags_noatime != flags_normal
                return noatime_used and atime_before == atime_after

        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_test_files()
        have_noatime = has_noatime('input/file1')
        self.cmd('create', self.repository_location + '::archive', 'input')
        self.cmd('create', self.repository_location + '::archive2', 'input')
        if has_lchflags:
            # remove the file we did not backup, so input and output become equal
            os.remove(os.path.join('input', 'flagfile'))
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        # mount the whole repository, archive contents shall show up in archivename subdirs of mountpoint:
        with self.fuse_mount(self.repository_location, mountpoint):
            # bsdflags are not supported by the FUSE mount
            # we also ignore xattrs here, they are tested separately
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'archive', 'input'),
                                   ignore_bsdflags=True, ignore_xattrs=True)
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'archive2', 'input'),
                                   ignore_bsdflags=True, ignore_xattrs=True)
        # mount only 1 archive, its contents shall show up directly in mountpoint:
        with self.fuse_mount(self.repository_location + '::archive', mountpoint):
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'input'),
                                   ignore_bsdflags=True, ignore_xattrs=True)
            # regular file
            in_fn = 'input/file1'
            out_fn = os.path.join(mountpoint, 'input', 'file1')
            # stat
            sti1 = os.stat(in_fn)
            sto1 = os.stat(out_fn)
            assert sti1.st_mode == sto1.st_mode
            assert sti1.st_uid == sto1.st_uid
            assert sti1.st_gid == sto1.st_gid
            assert sti1.st_size == sto1.st_size
            if have_noatime:
                assert sti1.st_atime == sto1.st_atime
            assert sti1.st_ctime == sto1.st_ctime
            assert sti1.st_mtime == sto1.st_mtime
            # note: there is another hardlink to this, see below
            assert sti1.st_nlink == sto1.st_nlink == 2
            # read
            with open(in_fn, 'rb') as in_f, open(out_fn, 'rb') as out_f:
                assert in_f.read() == out_f.read()
            # hardlink (to 'input/file1')
            if are_hardlinks_supported():
                in_fn = 'input/hardlink'
                out_fn = os.path.join(mountpoint, 'input', 'hardlink')
                sti2 = os.stat(in_fn)
                sto2 = os.stat(out_fn)
                assert sti2.st_nlink == sto2.st_nlink == 2
                assert sto1.st_ino == sto2.st_ino
            # symlink
            if are_symlinks_supported():
                in_fn = 'input/link1'
                out_fn = os.path.join(mountpoint, 'input', 'link1')
                sti = os.stat(in_fn, follow_symlinks=False)
                sto = os.stat(out_fn, follow_symlinks=False)
                assert stat.S_ISLNK(sti.st_mode)
                assert stat.S_ISLNK(sto.st_mode)
                assert os.readlink(in_fn) == os.readlink(out_fn)
            # FIFO
            if are_fifos_supported():
                out_fn = os.path.join(mountpoint, 'input', 'fifo1')
                sto = os.stat(out_fn)
                assert stat.S_ISFIFO(sto.st_mode)
            # list/read xattrs
            try:
                in_fn = 'input/fusexattr'
                out_fn = os.path.join(mountpoint, 'input', 'fusexattr')
                if not xattr.XATTR_FAKEROOT and xattr.is_enabled(self.input_path):
                    assert no_selinux(xattr.listxattr(out_fn)) == ['user.foo', ]
                    assert xattr.getxattr(out_fn, 'user.foo') == b'bar'
                else:
                    assert xattr.listxattr(out_fn) == []
                    try:
                        xattr.getxattr(out_fn, 'user.foo')
                    except OSError as e:
                        assert e.errno == llfuse.ENOATTR
                    else:
                        assert False, "expected OSError(ENOATTR), but no error was raised"
            except OSError as err:
                if sys.platform.startswith(('freebsd', )) and err.errno == errno.ENOTSUP:
                    # some systems have no xattr support on FUSE
                    pass
                else:
                    raise

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_versions_view(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('test', contents=b'first')
        if are_hardlinks_supported():
            self.create_regular_file('hardlink1', contents=b'')
            os.link('input/hardlink1', 'input/hardlink2')
        self.cmd('create', self.repository_location + '::archive1', 'input')
        self.create_regular_file('test', contents=b'second')
        self.cmd('create', self.repository_location + '::archive2', 'input')
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        # mount the whole repository, archive contents shall show up in versioned view:
        with self.fuse_mount(self.repository_location, mountpoint, '-o', 'versions'):
            path = os.path.join(mountpoint, 'input', 'test')  # filename shows up as directory ...
            files = os.listdir(path)
            assert all(f.startswith('test.') for f in files)  # ... with files test.xxxxxxxx in there
            assert {b'first', b'second'} == {open(os.path.join(path, f), 'rb').read() for f in files}
            if are_hardlinks_supported():
                st1 = os.stat(os.path.join(mountpoint, 'input', 'hardlink1', 'hardlink1.00000000'))
                st2 = os.stat(os.path.join(mountpoint, 'input', 'hardlink2', 'hardlink2.00000000'))
                assert st1.st_ino == st2.st_ino

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_allow_damaged_files(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('archive')
        # Get rid of a chunk and repair it
        archive, repository = self.open_archive('archive')
        with repository:
            for item in archive.iter_items():
                if item.path.endswith('testsuite/archiver.py'):
                    repository.delete(item.chunks[-1].id)
                    path = item.path  # store full path for later
                    break
            else:
                assert False  # missed the file
            repository.commit()
        self.cmd('check', '--repair', self.repository_location, exit_code=0)

        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        with self.fuse_mount(self.repository_location + '::archive', mountpoint):
            with pytest.raises(OSError) as excinfo:
                open(os.path.join(mountpoint, path))
            assert excinfo.value.errno == errno.EIO
        with self.fuse_mount(self.repository_location + '::archive', mountpoint, '-o', 'allow_damaged_files'):
            open(os.path.join(mountpoint, path)).close()

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_mount_options(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('arch11')
        self.create_src_archive('arch12')
        self.create_src_archive('arch21')
        self.create_src_archive('arch22')

        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        with self.fuse_mount(self.repository_location, mountpoint, '--first=2', '--sort=name'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ['arch11', 'arch12']
        with self.fuse_mount(self.repository_location, mountpoint, '--last=2', '--sort=name'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ['arch21', 'arch22']
        with self.fuse_mount(self.repository_location, mountpoint, '--prefix=arch1'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ['arch11', 'arch12']
        with self.fuse_mount(self.repository_location, mountpoint, '--prefix=arch2'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ['arch21', 'arch22']
        with self.fuse_mount(self.repository_location, mountpoint, '--prefix=arch'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == ['arch11', 'arch12', 'arch21', 'arch22']
        with self.fuse_mount(self.repository_location, mountpoint, '--prefix=nope'):
            assert sorted(os.listdir(os.path.join(mountpoint))) == []

    def verify_aes_counter_uniqueness(self, method):
        seen = set()  # Chunks already seen
        used = set()  # counter values already used

        def verify_uniqueness():
            with Repository(self.repository_path) as repository:
                for id, _ in repository.open_index(repository.get_transaction_id()).iteritems():
                    data = repository.get(id)
                    hash = sha256(data).digest()
                    if hash not in seen:
                        seen.add(hash)
                        num_blocks = num_aes_blocks(len(data) - 41)
                        nonce = bytes_to_long(data[33:41])
                        for counter in range(nonce, nonce + num_blocks):
                            self.assert_not_in(counter, used)
                            used.add(counter)

        self.create_test_files()
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        self.cmd('init', '--encryption=' + method, self.repository_location)
        verify_uniqueness()
        self.cmd('create', self.repository_location + '::test', 'input')
        verify_uniqueness()
        self.cmd('create', self.repository_location + '::test.2', 'input')
        verify_uniqueness()
        self.cmd('delete', self.repository_location + '::test.2')
        verify_uniqueness()

    def test_aes_counter_uniqueness_keyfile(self):
        self.verify_aes_counter_uniqueness('keyfile')

    def test_aes_counter_uniqueness_passphrase(self):
        self.verify_aes_counter_uniqueness('repokey')

    def test_debug_dump_archive_items(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            output = self.cmd('debug', 'dump-archive-items', self.repository_location + '::test')
        output_dir = sorted(os.listdir('output'))
        assert len(output_dir) > 0 and output_dir[0].startswith('000000_')
        assert 'Done.' in output

    def test_debug_dump_repo_objs(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            output = self.cmd('debug', 'dump-repo-objs', self.repository_location)
        output_dir = sorted(os.listdir('output'))
        assert len(output_dir) > 0 and output_dir[0].startswith('000000_')
        assert 'Done.' in output

    def test_debug_put_get_delete_obj(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        data = b'some data'
        hexkey = sha256(data).hexdigest()
        self.create_regular_file('file', contents=data)
        output = self.cmd('debug', 'put-obj', self.repository_location, 'input/file')
        assert hexkey in output
        output = self.cmd('debug', 'get-obj', self.repository_location, hexkey, 'output/file')
        assert hexkey in output
        with open('output/file', 'rb') as f:
            data_read = f.read()
        assert data == data_read
        output = self.cmd('debug', 'delete-obj', self.repository_location, hexkey)
        assert "deleted" in output
        output = self.cmd('debug', 'delete-obj', self.repository_location, hexkey)
        assert "not found" in output
        output = self.cmd('debug', 'delete-obj', self.repository_location, 'invalid')
        assert "is invalid" in output

    def test_init_interrupt(self):
        def raise_eof(*args):
            raise EOFError

        with patch.object(KeyfileKeyBase, 'create', raise_eof):
            self.cmd('init', '--encryption=repokey', self.repository_location, exit_code=1)
        assert not os.path.exists(self.repository_location)

    def check_cache(self):
        # First run a regular borg check
        self.cmd('check', self.repository_location)
        # Then check that the cache on disk matches exactly what's in the repo.
        with self.open_repository() as repository:
            manifest, key = Manifest.load(repository)
            with Cache(repository, key, manifest, sync=False) as cache:
                original_chunks = cache.chunks
            cache.destroy(repository)
            with Cache(repository, key, manifest) as cache:
                correct_chunks = cache.chunks
        assert original_chunks is not correct_chunks
        seen = set()
        for id, (refcount, size, csize) in correct_chunks.iteritems():
            o_refcount, o_size, o_csize = original_chunks[id]
            assert refcount == o_refcount
            assert size == o_size
            assert csize == o_csize
            seen.add(id)
        for id, (refcount, size, csize) in original_chunks.iteritems():
            assert id in seen

    def test_check_cache(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with self.open_repository() as repository:
            manifest, key = Manifest.load(repository)
            with Cache(repository, key, manifest, sync=False) as cache:
                cache.begin_txn()
                cache.chunks.incref(list(cache.chunks.iteritems())[0][0])
                cache.commit()
        with pytest.raises(AssertionError):
            self.check_cache()

    def test_recreate_target_rc(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('recreate', self.repository_location, '--target=asdf', exit_code=2)
        assert 'Need to specify single archive' in output

    def test_recreate_target(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.check_cache()
        archive = self.repository_location + '::test0'
        self.cmd('create', archive, 'input')
        self.check_cache()
        original_archive = self.cmd('list', self.repository_location)
        self.cmd('recreate', archive, 'input/dir2', '-e', 'input/dir2/file3', '--target=new-archive')
        self.check_cache()
        archives = self.cmd('list', self.repository_location)
        assert original_archive in archives
        assert 'new-archive' in archives

        archive = self.repository_location + '::new-archive'
        listing = self.cmd('list', '--short', archive)
        assert 'file1' not in listing
        assert 'dir2/file2' in listing
        assert 'dir2/file3' not in listing

    def test_recreate_basic(self):
        self.create_test_files()
        self.create_regular_file('dir2/file3', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        archive = self.repository_location + '::test0'
        self.cmd('create', archive, 'input')
        self.cmd('recreate', archive, 'input/dir2', '-e', 'input/dir2/file3')
        self.check_cache()
        listing = self.cmd('list', '--short', archive)
        assert 'file1' not in listing
        assert 'dir2/file2' in listing
        assert 'dir2/file3' not in listing

    @pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
    def test_recreate_subtree_hardlinks(self):
        # This is essentially the same problem set as in test_extract_hardlinks
        self._extract_hardlinks_setup()
        self.cmd('create', self.repository_location + '::test2', 'input')
        self.cmd('recreate', self.repository_location + '::test', 'input/dir1')
        self.check_cache()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert os.stat('input/dir1/hardlink').st_nlink == 2
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 2
            assert os.stat('input/dir1/aaaa').st_nlink == 2
            assert os.stat('input/dir1/source2').st_nlink == 2
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test2')
            assert os.stat('input/dir1/hardlink').st_nlink == 4

    def test_recreate_rechunkify(self):
        with open(os.path.join(self.input_path, 'large_file'), 'wb') as fd:
            fd.write(b'a' * 280)
            fd.write(b'b' * 280)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', '--chunker-params', '7,9,8,128', self.repository_location + '::test1', 'input')
        self.cmd('create', self.repository_location + '::test2', 'input', '--no-files-cache')
        list = self.cmd('list', self.repository_location + '::test1', 'input/large_file',
                        '--format', '{num_chunks} {unique_chunks}')
        num_chunks, unique_chunks = map(int, list.split(' '))
        # test1 and test2 do not deduplicate
        assert num_chunks == unique_chunks
        self.cmd('recreate', self.repository_location, '--chunker-params', 'default')
        self.check_cache()
        # test1 and test2 do deduplicate after recreate
        assert int(self.cmd('list', self.repository_location + '::test1', 'input/large_file', '--format={size}'))
        assert not int(self.cmd('list', self.repository_location + '::test1', 'input/large_file',
                                '--format', '{unique_chunks}'))

    def test_recreate_recompress(self):
        self.create_regular_file('compressible', size=10000)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', '-C', 'none')
        file_list = self.cmd('list', self.repository_location + '::test', 'input/compressible',
                             '--format', '{size} {csize} {sha256}')
        size, csize, sha256_before = file_list.split(' ')
        assert int(csize) >= int(size)  # >= due to metadata overhead
        self.cmd('recreate', self.repository_location, '-C', 'lz4')
        self.check_cache()
        file_list = self.cmd('list', self.repository_location + '::test', 'input/compressible',
                             '--format', '{size} {csize} {sha256}')
        size, csize, sha256_after = file_list.split(' ')
        assert int(csize) < int(size)
        assert sha256_before == sha256_after

    def test_recreate_dry_run(self):
        self.create_regular_file('compressible', size=10000)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        archives_before = self.cmd('list', self.repository_location + '::test')
        self.cmd('recreate', self.repository_location, '-n', '-e', 'input/compressible')
        self.check_cache()
        archives_after = self.cmd('list', self.repository_location + '::test')
        assert archives_after == archives_before

    def test_recreate_skips_nothing_to_do(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        info_before = self.cmd('info', self.repository_location + '::test')
        self.cmd('recreate', self.repository_location, '--chunker-params', 'default')
        self.check_cache()
        info_after = self.cmd('info', self.repository_location + '::test')
        assert info_before == info_after  # includes archive ID

    def test_with_lock(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        lock_path = os.path.join(self.repository_path, 'lock.exclusive')
        cmd = 'python3', '-c', 'import os, sys; sys.exit(42 if os.path.exists("%s") else 23)' % lock_path
        self.cmd('with-lock', self.repository_location, *cmd, fork=True, exit_code=42)

    def test_recreate_list_output(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=0)
        self.create_regular_file('file2', size=0)
        self.create_regular_file('file3', size=0)
        self.create_regular_file('file4', size=0)
        self.create_regular_file('file5', size=0)

        self.cmd('create', self.repository_location + '::test', 'input')

        output = self.cmd('recreate', '--list', '--info', self.repository_location + '::test', '-e', 'input/file2')
        self.check_cache()
        self.assert_in("input/file1", output)
        self.assert_in("x input/file2", output)

        output = self.cmd('recreate', '--list', self.repository_location + '::test', '-e', 'input/file3')
        self.check_cache()
        self.assert_in("input/file1", output)
        self.assert_in("x input/file3", output)

        output = self.cmd('recreate', self.repository_location + '::test', '-e', 'input/file4')
        self.check_cache()
        self.assert_not_in("input/file1", output)
        self.assert_not_in("x input/file4", output)

        output = self.cmd('recreate', '--info', self.repository_location + '::test', '-e', 'input/file5')
        self.check_cache()
        self.assert_not_in("input/file1", output)
        self.assert_not_in("x input/file5", output)

    def test_bad_filters(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('delete', '--first', '1', '--last', '1', self.repository_location, fork=True, exit_code=2)

    def test_key_export_keyfile(self):
        export_file = self.output_path + '/exported'
        self.cmd('init', self.repository_location, '--encryption', 'keyfile')
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd('key', 'export', self.repository_location, export_file)

        with open(export_file, 'r') as fd:
            export_contents = fd.read()

        assert export_contents.startswith('BORG_KEY ' + bin_to_hex(repo_id) + '\n')

        key_file = self.keys_path + '/' + os.listdir(self.keys_path)[0]

        with open(key_file, 'r') as fd:
            key_contents = fd.read()

        assert key_contents == export_contents

        os.unlink(key_file)

        self.cmd('key', 'import', self.repository_location, export_file)

        with open(key_file, 'r') as fd:
            key_contents2 = fd.read()

        assert key_contents2 == key_contents

    def test_key_export_repokey(self):
        export_file = self.output_path + '/exported'
        self.cmd('init', self.repository_location, '--encryption', 'repokey')
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd('key', 'export', self.repository_location, export_file)

        with open(export_file, 'r') as fd:
            export_contents = fd.read()

        assert export_contents.startswith('BORG_KEY ' + bin_to_hex(repo_id) + '\n')

        with Repository(self.repository_path) as repository:
            repo_key = RepoKey(repository)
            repo_key.load(None, Passphrase.env_passphrase())

        backup_key = KeyfileKey(key.TestKey.MockRepository())
        backup_key.load(export_file, Passphrase.env_passphrase())

        assert repo_key.enc_key == backup_key.enc_key

        with Repository(self.repository_path) as repository:
            repository.save_key(b'')

        self.cmd('key', 'import', self.repository_location, export_file)

        with Repository(self.repository_path) as repository:
            repo_key2 = RepoKey(repository)
            repo_key2.load(None, Passphrase.env_passphrase())

        assert repo_key2.enc_key == repo_key2.enc_key

    def test_key_import_errors(self):
        export_file = self.output_path + '/exported'
        self.cmd('init', self.repository_location, '--encryption', 'keyfile')

        self.cmd('key', 'import', self.repository_location, export_file, exit_code=EXIT_ERROR)

        with open(export_file, 'w') as fd:
            fd.write('something not a key\n')

        if self.FORK_DEFAULT:
            self.cmd('key', 'import', self.repository_location, export_file, exit_code=2)
        else:
            self.assert_raises(NotABorgKeyFile, lambda: self.cmd('key', 'import', self.repository_location, export_file))

        with open(export_file, 'w') as fd:
            fd.write('BORG_KEY a0a0a0\n')

        if self.FORK_DEFAULT:
            self.cmd('key', 'import', self.repository_location, export_file, exit_code=2)
        else:
            self.assert_raises(RepoIdMismatch, lambda: self.cmd('key', 'import', self.repository_location, export_file))

    def test_key_export_paperkey(self):
        repo_id = 'e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239'

        export_file = self.output_path + '/exported'
        self.cmd('init', self.repository_location, '--encryption', 'keyfile')
        self._set_repository_id(self.repository_path, unhexlify(repo_id))

        key_file = self.keys_path + '/' + os.listdir(self.keys_path)[0]

        with open(key_file, 'w') as fd:
            fd.write(KeyfileKey.FILE_ID + ' ' + repo_id + '\n')
            fd.write(b2a_base64(b'abcdefghijklmnopqrstu').decode())

        self.cmd('key', 'export', '--paper', self.repository_location, export_file)

        with open(export_file, 'r') as fd:
            export_contents = fd.read()

        assert export_contents == """To restore key use borg key import --paper /path/to/repo

BORG PAPER KEY v1
id: 2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02
 1: 616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d
 2: 737475 - 88
"""


@unittest.skipUnless('binary' in BORG_EXES, 'no borg.exe available')
class ArchiverTestCaseBinary(ArchiverTestCase):
    EXE = 'borg.exe'
    FORK_DEFAULT = True

    @unittest.skip('patches objects')
    def test_init_interrupt(self):
        pass

    @unittest.skip('test_basic_functionality seems incompatible with fakeroot and/or the binary.')
    def test_basic_functionality(self):
        pass

    @unittest.skip('test_overwrite seems incompatible with fakeroot and/or the binary.')
    def test_overwrite(self):
        pass

    def test_fuse(self):
        if fakeroot_detected():
            unittest.skip('test_fuse with the binary is not compatible with fakeroot')
        else:
            super().test_fuse()


class ArchiverCheckTestCase(ArchiverTestCaseBase):

    def setUp(self):
        super().setUp()
        with patch.object(ChunkBuffer, 'BUFFER_SIZE', 10):
            self.cmd('init', '--encryption=repokey', self.repository_location)
            self.create_src_archive('archive1')
            self.create_src_archive('archive2')

    def test_check_usage(self):
        output = self.cmd('check', '-v', '--progress', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)
        self.assert_in('Checking segments', output)
        # reset logging to new process default to avoid need for fork=True on next check
        logging.getLogger('borg.output.progress').setLevel(logging.NOTSET)
        output = self.cmd('check', '-v', '--repository-only', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_not_in('Starting archive consistency check', output)
        self.assert_not_in('Checking segments', output)
        output = self.cmd('check', '-v', '--archives-only', self.repository_location, exit_code=0)
        self.assert_not_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)
        output = self.cmd('check', '-v', '--archives-only', '--prefix=archive2', self.repository_location, exit_code=0)
        self.assert_not_in('archive1', output)
        output = self.cmd('check', '-v', '--archives-only', '--first=1', self.repository_location, exit_code=0)
        self.assert_in('archive1', output)
        self.assert_not_in('archive2', output)
        output = self.cmd('check', '-v', '--archives-only', '--last=1', self.repository_location, exit_code=0)
        self.assert_not_in('archive1', output)
        self.assert_in('archive2', output)

    def test_missing_file_chunk(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            for item in archive.iter_items():
                if item.path.endswith('testsuite/archiver.py'):
                    valid_chunks = item.chunks
                    killed_chunk = valid_chunks[-1]
                    repository.delete(killed_chunk.id)
                    break
            else:
                self.assert_true(False)  # should not happen
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        output = self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.assert_in('New missing file chunk detected', output)
        self.cmd('check', self.repository_location, exit_code=0)
        output = self.cmd('list', '--format={health}#{path}{LF}', self.repository_location + '::archive1', exit_code=0)
        self.assert_in('broken#', output)
        # check that the file in the old archives has now a different chunk list without the killed chunk
        for archive_name in ('archive1', 'archive2'):
            archive, repository = self.open_archive(archive_name)
            with repository:
                for item in archive.iter_items():
                    if item.path.endswith('testsuite/archiver.py'):
                        self.assert_not_equal(valid_chunks, item.chunks)
                        self.assert_not_in(killed_chunk, item.chunks)
                        break
                else:
                    self.assert_true(False)  # should not happen
        # do a fresh backup (that will include the killed chunk)
        with patch.object(ChunkBuffer, 'BUFFER_SIZE', 10):
            self.create_src_archive('archive3')
        # check should be able to heal the file now:
        output = self.cmd('check', '-v', '--repair', self.repository_location, exit_code=0)
        self.assert_in('Healed previously missing file chunk', output)
        self.assert_in('testsuite/archiver.py: Completely healed previously damaged file!', output)
        # check that the file in the old archives has the correct chunks again
        for archive_name in ('archive1', 'archive2'):
            archive, repository = self.open_archive(archive_name)
            with repository:
                for item in archive.iter_items():
                    if item.path.endswith('testsuite/archiver.py'):
                        self.assert_equal(valid_chunks, item.chunks)
                        break
                else:
                    self.assert_true(False)  # should not happen
        # list is also all-healthy again
        output = self.cmd('list', '--format={health}#{path}{LF}', self.repository_location + '::archive1', exit_code=0)
        self.assert_not_in('broken#', output)

    def test_missing_archive_item_chunk(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            repository.delete(archive.metadata.items[-5])
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_missing_archive_metadata(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            repository.delete(archive.id)
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_missing_manifest(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            repository.delete(Manifest.MANIFEST_ID)
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        output = self.cmd('check', '-v', '--repair', self.repository_location, exit_code=0)
        self.assert_in('archive1', output)
        self.assert_in('archive2', output)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_corrupted_manifest(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b'corrupted!'
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        output = self.cmd('check', '-v', '--repair', self.repository_location, exit_code=0)
        self.assert_in('archive1', output)
        self.assert_in('archive2', output)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_manifest_rebuild_corrupted_chunk(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b'corrupted!'
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)

            chunk = repository.get(archive.id)
            corrupted_chunk = chunk + b'corrupted!'
            repository.put(archive.id, corrupted_chunk)
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        output = self.cmd('check', '-v', '--repair', self.repository_location, exit_code=0)
        self.assert_in('archive2', output)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_manifest_rebuild_duplicate_archive(self):
        archive, repository = self.open_archive('archive1')
        key = archive.key
        with repository:
            manifest = repository.get(Manifest.MANIFEST_ID)
            corrupted_manifest = manifest + b'corrupted!'
            repository.put(Manifest.MANIFEST_ID, corrupted_manifest)

            archive = msgpack.packb({
                'cmdline': [],
                'items': [],
                'hostname': 'foo',
                'username': 'bar',
                'name': 'archive1',
                'time': '2016-12-15T18:49:51.849711',
                'version': 1,
            })
            archive_id = key.id_hash(archive)
            repository.put(archive_id, key.encrypt(Chunk(archive)))
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        output = self.cmd('list', self.repository_location)
        self.assert_in('archive1', output)
        self.assert_in('archive1.1', output)
        self.assert_in('archive2', output)

    def test_extra_chunks(self):
        self.cmd('check', self.repository_location, exit_code=0)
        with Repository(self.repository_location, exclusive=True) as repository:
            repository.put(b'01234567890123456789012345678901', b'xxxx')
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)
        self.cmd('extract', '--dry-run', self.repository_location + '::archive1', exit_code=0)

    def _test_verify_data(self, *init_args):
        shutil.rmtree(self.repository_path)
        self.cmd('init', self.repository_location, *init_args)
        self.create_src_archive('archive1')
        archive, repository = self.open_archive('archive1')
        with repository:
            for item in archive.iter_items():
                if item.path.endswith('testsuite/archiver.py'):
                    chunk = item.chunks[-1]
                    data = repository.get(chunk.id) + b'1234'
                    repository.put(chunk.id, data)
                    break
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=0)
        output = self.cmd('check', '--verify-data', self.repository_location, exit_code=1)
        assert bin_to_hex(chunk.id) + ', integrity error' in output
        # repair (heal is tested in another test)
        output = self.cmd('check', '--repair', '--verify-data', self.repository_location, exit_code=0)
        assert bin_to_hex(chunk.id) + ', integrity error' in output
        assert 'testsuite/archiver.py: New missing file chunk detected' in output

    def test_verify_data(self):
        self._test_verify_data('--encryption', 'repokey')

    def test_verify_data_unencrypted(self):
        self._test_verify_data('--encryption', 'none')

    def test_empty_repository(self):
        with Repository(self.repository_location, exclusive=True) as repository:
            for id_ in repository.list():
                repository.delete(id_)
            repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)

    def test_attic013_acl_bug(self):
        # Attic up to release 0.13 contained a bug where every item unintentionally received
        # a b'acl'=None key-value pair.
        # This bug can still live on in Borg repositories (through borg upgrade).
        class Attic013Item:
            def as_dict():
                return {
                    # These are required
                    b'path': '1234',
                    b'mtime': 0,
                    b'mode': 0,
                    b'user': b'0',
                    b'group': b'0',
                    b'uid': 0,
                    b'gid': 0,
                    # acl is the offending key.
                    b'acl': None,
                }

        archive, repository = self.open_archive('archive1')
        with repository:
            manifest, key = Manifest.load(repository)
            with Cache(repository, key, manifest) as cache:
                archive = Archive(repository, key, manifest, '0.13', cache=cache, create=True)
                archive.items_buffer.add(Attic013Item)
                archive.save()
        self.cmd('check', self.repository_location, exit_code=0)
        self.cmd('list', self.repository_location + '::0.13', exit_code=0)


class ManifestAuthenticationTest(ArchiverTestCaseBase):
    def spoof_manifest(self, repository):
        with repository:
            _, key = Manifest.load(repository)
            repository.put(Manifest.MANIFEST_ID, key.encrypt(Chunk(msgpack.packb({
                'version': 1,
                'archives': {},
                'config': {},
                'timestamp': (datetime.utcnow() + timedelta(days=1)).isoformat(),
            }))))
            repository.commit()

    def test_fresh_init_tam_required(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest, key = Manifest.load(repository)
            repository.put(Manifest.MANIFEST_ID, key.encrypt(Chunk(msgpack.packb({
                'version': 1,
                'archives': {},
                'timestamp': (datetime.utcnow() + timedelta(days=1)).isoformat(),
            }))))
            repository.commit()

        with pytest.raises(TAMRequiredError):
            self.cmd('list', self.repository_location)

    def test_not_required(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('archive1234')
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            shutil.rmtree(get_security_dir(bin_to_hex(repository.id)))
            _, key = Manifest.load(repository)
            key.tam_required = False
            key.change_passphrase(key._passphrase)

            manifest = msgpack.unpackb(key.decrypt(None, repository.get(Manifest.MANIFEST_ID)).data)
            del manifest[b'tam']
            repository.put(Manifest.MANIFEST_ID, key.encrypt(Chunk(msgpack.packb(manifest))))
            repository.commit()
        output = self.cmd('list', '--debug', self.repository_location)
        assert 'archive1234' in output
        assert 'TAM not found and not required' in output
        # Run upgrade
        self.cmd('upgrade', '--tam', self.repository_location)
        # Manifest must be authenticated now
        output = self.cmd('list', '--debug', self.repository_location)
        assert 'archive1234' in output
        assert 'TAM-verified manifest' in output
        # Try to spoof / modify pre-1.0.9
        self.spoof_manifest(repository)
        # Fails
        with pytest.raises(TAMRequiredError):
            self.cmd('list', self.repository_location)
        # Force upgrade
        self.cmd('upgrade', '--tam', '--force', self.repository_location)
        self.cmd('list', self.repository_location)

    def test_disable(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('archive1234')
        self.cmd('upgrade', '--disable-tam', self.repository_location)
        repository = Repository(self.repository_path, exclusive=True)
        self.spoof_manifest(repository)
        assert not self.cmd('list', self.repository_location)

    def test_disable2(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('archive1234')
        repository = Repository(self.repository_path, exclusive=True)
        self.spoof_manifest(repository)
        self.cmd('upgrade', '--disable-tam', self.repository_location)
        assert not self.cmd('list', self.repository_location)


@pytest.mark.skipif(sys.platform == 'cygwin', reason='remote is broken on cygwin and hangs')
class RemoteArchiverTestCase(ArchiverTestCase):
    prefix = '__testsuite__:'

    def open_repository(self):
        return RemoteRepository(Location(self.repository_location))

    def test_remote_repo_restrict_to_path(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', self.repository_path]):
            self.cmd('init', '--encryption=repokey', self.repository_location)
        # restricted to repo directory itself, fail for other directories with same prefix:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', self.repository_path]):
            self.assert_raises(PathNotAllowed,
                               lambda: self.cmd('init', '--encryption=repokey', self.repository_location + '_0'))

        # restricted to a completely different path:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo']):
            self.assert_raises(PathNotAllowed,
                               lambda: self.cmd('init', '--encryption=repokey', self.repository_location + '_1'))
        path_prefix = os.path.dirname(self.repository_path)
        # restrict to repo directory's parent directory:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', path_prefix]):
            self.cmd('init', self.repository_location + '_2')
        # restrict to repo directory's parent directory and another directory:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo', '--restrict-to-path', path_prefix]):
            self.cmd('init', self.repository_location + '_3')

    @unittest.skip('only works locally')
    def test_debug_put_get_delete_obj(self):
        pass

    def test_strip_components_doesnt_leak(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('dir/file', contents=b"test file contents 1")
        self.create_regular_file('dir/file2', contents=b"test file contents 2")
        self.create_regular_file('skipped-file1', contents=b"test file contents 3")
        self.create_regular_file('skipped-file2', contents=b"test file contents 4")
        self.create_regular_file('skipped-file3', contents=b"test file contents 5")
        self.cmd('create', self.repository_location + '::test', 'input')
        marker = 'cached responses left in RemoteRepository'
        with changedir('output'):
            res = self.cmd('extract', "--debug", self.repository_location + '::test', '--strip-components', '3')
            self.assert_true(marker not in res)
            with self.assert_creates_file('file'):
                res = self.cmd('extract', "--debug", self.repository_location + '::test', '--strip-components', '2')
                self.assert_true(marker not in res)
            with self.assert_creates_file('dir/file'):
                res = self.cmd('extract', "--debug", self.repository_location + '::test', '--strip-components', '1')
                self.assert_true(marker not in res)
            with self.assert_creates_file('input/dir/file'):
                res = self.cmd('extract', "--debug", self.repository_location + '::test', '--strip-components', '0')
                self.assert_true(marker not in res)


class DiffArchiverTestCase(ArchiverTestCaseBase):
    def test_basic_functionality(self):
        # Initialize test folder
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)

        # Setup files for the first snapshot
        self.create_regular_file('file_unchanged', size=128)
        self.create_regular_file('file_removed', size=256)
        self.create_regular_file('file_removed2', size=512)
        self.create_regular_file('file_replaced', size=1024)
        os.mkdir('input/dir_replaced_with_file')
        os.chmod('input/dir_replaced_with_file', stat.S_IFDIR | 0o755)
        os.mkdir('input/dir_removed')
        if are_symlinks_supported():
            os.mkdir('input/dir_replaced_with_link')
            os.symlink('input/dir_replaced_with_file', 'input/link_changed')
            os.symlink('input/file_unchanged', 'input/link_removed')
            os.symlink('input/file_removed2', 'input/link_target_removed')
            os.symlink('input/empty', 'input/link_target_contents_changed')
            os.symlink('input/empty', 'input/link_replaced_by_file')
        if are_hardlinks_supported():
            os.link('input/empty', 'input/hardlink_contents_changed')
            os.link('input/file_removed', 'input/hardlink_removed')
            os.link('input/file_removed2', 'input/hardlink_target_removed')
            os.link('input/file_replaced', 'input/hardlink_target_replaced')

        # Create the first snapshot
        self.cmd('create', self.repository_location + '::test0', 'input')

        # Setup files for the second snapshot
        self.create_regular_file('file_added', size=2048)
        os.unlink('input/file_removed')
        os.unlink('input/file_removed2')
        os.unlink('input/file_replaced')
        self.create_regular_file('file_replaced', size=4096, contents=b'0')
        os.rmdir('input/dir_replaced_with_file')
        self.create_regular_file('dir_replaced_with_file', size=8192)
        os.chmod('input/dir_replaced_with_file', stat.S_IFREG | 0o755)
        os.mkdir('input/dir_added')
        os.rmdir('input/dir_removed')
        if are_symlinks_supported():
            os.rmdir('input/dir_replaced_with_link')
            os.symlink('input/dir_added', 'input/dir_replaced_with_link')
            os.unlink('input/link_changed')
            os.symlink('input/dir_added', 'input/link_changed')
            os.symlink('input/dir_added', 'input/link_added')
            os.unlink('input/link_replaced_by_file')
            self.create_regular_file('link_replaced_by_file', size=16384)
            os.unlink('input/link_removed')
        if are_hardlinks_supported():
            os.unlink('input/hardlink_removed')
            os.link('input/file_added', 'input/hardlink_added')

        with open('input/empty', 'ab') as fd:
            fd.write(b'appended_data')

        # Create the second snapshot
        self.cmd('create', self.repository_location + '::test1a', 'input')
        self.cmd('create', '--chunker-params', '16,18,17,4095', self.repository_location + '::test1b', 'input')

        def do_asserts(output, archive):
            # File contents changed (deleted and replaced with a new file)
            assert 'B input/file_replaced' in output

            # File unchanged
            assert 'input/file_unchanged' not in output

            # Directory replaced with a regular file
            if 'BORG_TESTS_IGNORE_MODES' not in os.environ:
                assert '[drwxr-xr-x -> -rwxr-xr-x] input/dir_replaced_with_file' in output

            # Basic directory cases
            assert 'added directory     input/dir_added' in output
            assert 'removed directory   input/dir_removed' in output

            if are_symlinks_supported():
                # Basic symlink cases
                assert 'changed link        input/link_changed' in output
                assert 'added link          input/link_added' in output
                assert 'removed link        input/link_removed' in output

                # Symlink replacing or being replaced
                assert '] input/dir_replaced_with_link' in output
                assert '] input/link_replaced_by_file' in output

                # Symlink target removed. Should not affect the symlink at all.
                assert 'input/link_target_removed' not in output

            # The inode has two links and the file contents changed. Borg
            # should notice the changes in both links. However, the symlink
            # pointing to the file is not changed.
            assert '0 B input/empty' in output
            if are_hardlinks_supported():
                assert '0 B input/hardlink_contents_changed' in output
            if are_symlinks_supported():
                assert 'input/link_target_contents_changed' not in output

            # Added a new file and a hard link to it. Both links to the same
            # inode should appear as separate files.
            assert 'added       2.05 kB input/file_added' in output
            if are_hardlinks_supported():
                assert 'added       2.05 kB input/hardlink_added' in output

            # The inode has two links and both of them are deleted. They should
            # appear as two deleted files.
            assert 'removed       256 B input/file_removed' in output
            if are_hardlinks_supported():
                assert 'removed       256 B input/hardlink_removed' in output

            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should not change this link at all.
            if are_hardlinks_supported():
                assert 'input/hardlink_target_removed' not in output

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should not
            # change this link at all.
            if are_hardlinks_supported():
                assert 'input/hardlink_target_replaced' not in output

        do_asserts(self.cmd('diff', self.repository_location + '::test0', 'test1a'), '1a')
        # We expect exit_code=1 due to the chunker params warning
        do_asserts(self.cmd('diff', self.repository_location + '::test0', 'test1b', exit_code=1), '1b')

    def test_sort_option(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)

        self.create_regular_file('a_file_removed', size=8)
        self.create_regular_file('f_file_removed', size=16)
        self.create_regular_file('c_file_changed', size=32)
        self.create_regular_file('e_file_changed', size=64)
        self.cmd('create', self.repository_location + '::test0', 'input')

        os.unlink('input/a_file_removed')
        os.unlink('input/f_file_removed')
        os.unlink('input/c_file_changed')
        os.unlink('input/e_file_changed')
        self.create_regular_file('c_file_changed', size=512)
        self.create_regular_file('e_file_changed', size=1024)
        self.create_regular_file('b_file_added', size=128)
        self.create_regular_file('d_file_added', size=256)
        self.cmd('create', self.repository_location + '::test1', 'input')

        output = self.cmd('diff', '--sort', self.repository_location + '::test0', 'test1')
        expected = [
            'a_file_removed',
            'b_file_added',
            'c_file_changed',
            'd_file_added',
            'e_file_changed',
            'f_file_removed',
        ]

        assert all(x in line for x, line in zip(expected, output.splitlines()))


def test_get_args():
    archiver = Archiver()
    # everything normal:
    # first param is argv as produced by ssh forced command,
    # second param is like from SSH_ORIGINAL_COMMAND env variable
    args = archiver.get_args(['borg', 'serve', '--restrict-to-path=/p1', '--restrict-to-path=/p2', ],
                             'borg serve --info --umask=0027')
    assert args.func == archiver.do_serve
    assert args.restrict_to_paths == ['/p1', '/p2']
    assert args.umask == 0o027
    assert args.log_level == 'info'
    # trying to cheat - break out of path restriction
    args = archiver.get_args(['borg', 'serve', '--restrict-to-path=/p1', '--restrict-to-path=/p2', ],
                             'borg serve --restrict-to-path=/')
    assert args.restrict_to_paths == ['/p1', '/p2']
    # trying to cheat - try to execute different subcommand
    args = archiver.get_args(['borg', 'serve', '--restrict-to-path=/p1', '--restrict-to-path=/p2', ],
                             'borg init /')
    assert args.func == archiver.do_serve


def test_compare_chunk_contents():
    def ccc(a, b):
        chunks_a = [Chunk(data) for data in a]
        chunks_b = [Chunk(data) for data in b]
        compare1 = Archiver.compare_chunk_contents(iter(chunks_a), iter(chunks_b))
        compare2 = Archiver.compare_chunk_contents(iter(chunks_b), iter(chunks_a))
        assert compare1 == compare2
        return compare1
    assert ccc([
        b'1234', b'567A', b'bC'
    ], [
        b'1', b'23', b'4567A', b'b', b'C'
    ])
    # one iterator exhausted before the other
    assert not ccc([
        b'12345',
    ], [
        b'1234', b'56'
    ])
    # content mismatch
    assert not ccc([
        b'1234', b'65'
    ], [
        b'1234', b'56'
    ])
    # first is the prefix of second
    assert not ccc([
        b'1234', b'56'
    ], [
        b'1234', b'565'
    ])


class TestBuildFilter:
    @staticmethod
    def peek_and_store_hardlink_masters(item, matched):
        pass

    def test_basic(self):
        matcher = PatternMatcher()
        matcher.add([parse_pattern('included')], True)
        filter = Archiver.build_filter(matcher, self.peek_and_store_hardlink_masters, 0)
        assert filter(Item(path='included'))
        assert filter(Item(path='included/file'))
        assert not filter(Item(path='something else'))

    def test_empty(self):
        matcher = PatternMatcher(fallback=True)
        filter = Archiver.build_filter(matcher, self.peek_and_store_hardlink_masters, 0)
        assert filter(Item(path='anything'))

    def test_strip_components(self):
        matcher = PatternMatcher(fallback=True)
        filter = Archiver.build_filter(matcher, self.peek_and_store_hardlink_masters, strip_components=1)
        assert not filter(Item(path='shallow'))
        assert not filter(Item(path='shallow/'))  # can this even happen? paths are normalized...
        assert filter(Item(path='deep enough/file'))
        assert filter(Item(path='something/dir/file'))
