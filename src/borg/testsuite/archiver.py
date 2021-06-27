import argparse
import errno
import io
import json
import logging
import os
import pstats
import random
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import re
import unittest
from binascii import unhexlify, b2a_base64
from configparser import ConfigParser
from datetime import datetime
from datetime import timezone
from datetime import timedelta
from hashlib import sha256
from io import BytesIO, StringIO
from unittest.mock import patch

import pytest

try:
    import llfuse
except ImportError:
    pass

import borg
from .. import xattr, helpers, platform
from ..archive import Archive, ChunkBuffer, flags_noatime, flags_normal
from ..archiver import Archiver, parse_storage_quota, PURE_PYTHON_MSGPACK_WARNING
from ..cache import Cache, LocalCache
from ..constants import *  # NOQA
from ..crypto.low_level import bytes_to_long, num_aes_blocks
from ..crypto.key import KeyfileKeyBase, RepoKey, KeyfileKey, Passphrase, TAMRequiredError
from ..crypto.keymanager import RepoIdMismatch, NotABorgKeyFile
from ..crypto.file_integrity import FileIntegrityError
from ..helpers import Location, get_security_dir
from ..helpers import Manifest, MandatoryFeatureUnsupported
from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from ..helpers import bin_to_hex
from ..helpers import MAX_S
from ..helpers import msgpack
from ..nanorst import RstToTextLazy, rst_to_terminal
from ..patterns import IECommand, PatternMatcher, parse_pattern
from ..item import Item
from ..locking import LockFailed
from ..logger import setup_logging
from ..remote import RemoteRepository, PathNotAllowed
from ..repository import Repository
from . import has_lchflags, has_llfuse
from . import BaseTestCase, changedir, environment_variable, no_selinux
from . import are_symlinks_supported, are_hardlinks_supported, are_fifos_supported, is_utime_fully_supported, is_birthtime_fully_supported
from .platform import fakeroot_detected
from .upgrader import make_attic_repo
from . import key


src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def exec_cmd(*args, archiver=None, fork=False, exe=None, input=b'', binary_output=False, **kw):
    if fork:
        try:
            if exe is None:
                borg = (sys.executable, '-m', 'borg.archiver')
            elif isinstance(exe, str):
                borg = (exe, )
            elif not isinstance(exe, tuple):
                raise ValueError('exe must be None, a tuple or a str')
            output = subprocess.check_output(borg + args, stderr=subprocess.STDOUT, input=input)
            ret = 0
        except subprocess.CalledProcessError as e:
            output = e.output
            ret = e.returncode
        except SystemExit as e:  # possibly raised by argparse
            output = ''
            ret = e.code
        if binary_output:
            return ret, output
        else:
            return ret, os.fsdecode(output)
    else:
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = StringIO(input.decode())
            sys.stdin.buffer = BytesIO(input)
            output = BytesIO()
            # Always use utf-8 here, to simply .decode() below
            output_text = sys.stdout = sys.stderr = io.TextIOWrapper(output, encoding='utf-8')
            if archiver is None:
                archiver = Archiver()
            archiver.prerun_checks = lambda *args: None
            archiver.exit_code = EXIT_SUCCESS
            helpers.exit_code = EXIT_SUCCESS
            try:
                args = archiver.parse_args(list(args))
                # argparse parsing may raise SystemExit when the command line is bad or
                # actions that abort early (eg. --help) where given. Catch this and return
                # the error code as-if we invoked a Borg binary.
            except SystemExit as e:
                output_text.flush()
                return e.code, output.getvalue() if binary_output else output.getvalue().decode()
            ret = archiver.run(args)
            output_text.flush()
            return ret, output.getvalue() if binary_output else output.getvalue().decode()
        finally:
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr


def have_gnutar():
    if not shutil.which('tar'):
        return False
    popen = subprocess.Popen(['tar', '--version'], stdout=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    return b'GNU tar' in stdout


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
        os.environ['BORG_PASSPHRASE'] = 'waytooeasyonlyfortests'
        os.environ['BORG_SELFTEST'] = 'disabled'
        self.archiver = not self.FORK_DEFAULT and Archiver() or None
        self.tmpdir = tempfile.mkdtemp()
        self.repository_path = os.path.join(self.tmpdir, 'repository')
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        self.keys_path = os.path.join(self.tmpdir, 'keys')
        self.cache_path = os.path.join(self.tmpdir, 'cache')
        self.exclude_file_path = os.path.join(self.tmpdir, 'excludes')
        self.patterns_file_path = os.path.join(self.tmpdir, 'patterns')
        os.environ['BORG_KEYS_DIR'] = self.keys_path
        os.environ['BORG_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.chmod(self.input_path, 0o777)  # avoid troubles with fakeroot / FUSE
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b'input/file2\n# A comment line, then a blank line\n\n')
        with open(self.patterns_file_path, 'wb') as fd:
            fd.write(b'+input/file_important\n- input/file*\n# A comment line, then a blank line\n\n')
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._old_wd)
        # note: ignore_errors=True as workaround for issue #862
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        setup_logging()

    def cmd(self, *args, **kw):
        exit_code = kw.pop('exit_code', 0)
        fork = kw.pop('fork', None)
        binary_output = kw.get('binary_output', False)
        if fork is None:
            fork = self.FORK_DEFAULT
        ret, output = exec_cmd(*args, fork=fork, exe=self.EXE, archiver=self.archiver, **kw)
        if ret != exit_code:
            print(output)
        self.assert_equal(ret, exit_code)
        # if tests are run with the pure-python msgpack, there will be warnings about
        # this in the output, which would make a lot of tests fail.
        pp_msg = PURE_PYTHON_MSGPACK_WARNING.encode() if binary_output else PURE_PYTHON_MSGPACK_WARNING
        empty = b'' if binary_output else ''
        output = empty.join(line for line in output.splitlines(keepends=True)
                            if pp_msg not in line)
        return output

    def create_src_archive(self, name):
        self.cmd('create', '--compression=lz4', self.repository_location + '::' + name, src_dir)

    def open_archive(self, name):
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(repository, key, manifest, name)
        return archive, repository

    def open_repository(self):
        return Repository(self.repository_path, exclusive=True)

    def create_regular_file(self, name, size=0, contents=None):
        assert not (size != 0 and contents and len(contents) != size), 'size and contents do not match'
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
            # ironically, due to the way how fakeroot works, comparing FUSE file xattrs to orig file xattrs
            # will FAIL if fakeroot supports xattrs, thus we only set the xattr if XATTR_FAKEROOT is False.
            # This is because fakeroot with xattr-support does not propagate xattrs of the underlying file
            # into "fakeroot space". Because the xattrs exposed by borgfs are these of an underlying file
            # (from fakeroots point of view) they are invisible to the test process inside the fakeroot.
            xattr.setxattr(os.path.join(self.input_path, 'fusexattr'), 'user.foo', b'bar')
            xattr.setxattr(os.path.join(self.input_path, 'fusexattr'), 'user.empty', b'')
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
        time.sleep(1)  # "empty" must have newer timestamp than other files
        self.create_regular_file('empty', size=0)
        return have_root


class ArchiverTestCase(ArchiverTestCaseBase):
    requires_hardlinks = pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')

    def test_basic_functionality(self):
        have_root = self.create_test_files()
        # fork required to test show-rc output
        output = self.cmd('init', '--encryption=repokey', '--show-version', '--show-rc', self.repository_location, fork=True)
        self.assert_in('borgbackup version', output)
        self.assert_in('terminating with success status, rc 0', output)
        self.cmd('create', '--exclude-nodump', self.repository_location + '::test', 'input')
        output = self.cmd('create', '--exclude-nodump', '--stats', self.repository_location + '::test.2', 'input')
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

    @requires_hardlinks
    def test_create_duplicate_root(self):
        # setup for #5603
        path_a = os.path.join(self.input_path, 'a')
        path_b = os.path.join(self.input_path, 'b')
        os.mkdir(path_a)
        os.mkdir(path_b)
        hl_a = os.path.join(path_a, 'hardlink')
        hl_b = os.path.join(path_b, 'hardlink')
        self.create_regular_file(hl_a, contents=b'123456')
        os.link(hl_a, hl_b)
        self.cmd('init', '--encryption=none', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', 'input')  # give input twice!
        # test if created archive has 'input' contents twice:
        archive_list = self.cmd('list', '--json-lines', self.repository_location + '::test')
        paths = [json.loads(line)['path'] for line in archive_list.split('\n') if line]
        # we have all fs items exactly once!
        assert sorted(paths) == ['input', 'input/a', 'input/a/hardlink', 'input/b', 'input/b/hardlink']

    def test_init_parent_dirs(self):
        parent_path = os.path.join(self.tmpdir, 'parent1', 'parent2')
        repository_path = os.path.join(parent_path, 'repository')
        repository_location = self.prefix + repository_path
        with pytest.raises(Repository.ParentPathDoesNotExist):
            # normal borg init does NOT create missing parent dirs
            self.cmd('init', '--encryption=none', repository_location)
        # but if told so, it does:
        self.cmd('init', '--encryption=none', '--make-parent-dirs', repository_location)
        assert os.path.exists(parent_path)

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

    @pytest.mark.skipif(not is_utime_fully_supported(), reason='cannot properly setup and execute test without utime')
    @pytest.mark.skipif(not is_birthtime_fully_supported(), reason='cannot properly setup and execute test without birthtime')
    def test_birthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime('input/file1', (atime, birthtime))
        os.utime('input/file1', (atime, mtime))
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        sti = os.stat('input/file1')
        sto = os.stat('output/input/file1')
        assert int(sti.st_birthtime * 1e9) == int(sto.st_birthtime * 1e9) == birthtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

    @pytest.mark.skipif(not is_utime_fully_supported(), reason='cannot properly setup and execute test without utime')
    @pytest.mark.skipif(not is_birthtime_fully_supported(), reason='cannot properly setup and execute test without birthtime')
    def test_nobirthtime(self):
        self.create_test_files()
        birthtime, mtime, atime = 946598400, 946684800, 946771200
        os.utime('input/file1', (atime, birthtime))
        os.utime('input/file1', (atime, mtime))
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', '--nobirthtime', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        sti = os.stat('input/file1')
        sto = os.stat('output/input/file1')
        assert int(sti.st_birthtime * 1e9) == birthtime * 1e9
        assert int(sto.st_birthtime * 1e9) == mtime * 1e9
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9

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
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd('create', self.repository_location + '::test.2', 'input')

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
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd('create', self.repository_location + '_encrypted::test.2', 'input')

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
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd('create', self.repository_location + '::test.2', 'input')

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

    def test_repository_swap_detection_repokey_blank_passphrase(self):
        # Check that a repokey repo with a blank passphrase is considered like a plaintext repo.
        self.create_test_files()
        # User initializes her repository with her passphrase
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        # Attacker replaces it with her own repository, which is encrypted but has no passphrase set
        shutil.rmtree(self.repository_path)
        with environment_variable(BORG_PASSPHRASE=''):
            self.cmd('init', '--encryption=repokey', self.repository_location)
            # Delete cache & security database, AKA switch to user perspective
            self.cmd('delete', '--cache-only', self.repository_location)
            repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
            shutil.rmtree(get_security_dir(repository_id))
        with environment_variable(BORG_PASSPHRASE=None):
            # This is the part were the user would be tricked, e.g. she assumes that BORG_PASSPHRASE
            # is set, while it isn't. Previously this raised no warning,
            # since the repository is, technically, encrypted.
            if self.FORK_DEFAULT:
                self.cmd('create', self.repository_location + '::test.2', 'input', exit_code=EXIT_ERROR)
            else:
                with pytest.raises(Cache.CacheInitAbortedError):
                    self.cmd('create', self.repository_location + '::test.2', 'input')

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

        self.create_regular_file('source', contents=b'123456')
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

    @requires_hardlinks
    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_mount_hardlinks(self):
        self._extract_hardlinks_setup()
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        # we need to get rid of permissions checking because fakeroot causes issues with it.
        # On all platforms, borg defaults to "default_permissions" and we need to get rid of it via "ignore_permissions".
        # On macOS (darwin), we additionally need "defer_permissions" to switch off the checks in osxfuse.
        if sys.platform == 'darwin':
            ignore_perms = ['-o', 'ignore_permissions,defer_permissions']
        else:
            ignore_perms = ['-o', 'ignore_permissions']
        with self.fuse_mount(self.repository_location + '::test', mountpoint, '--strip-components=2', *ignore_perms), \
             changedir(mountpoint):
            assert os.stat('hardlink').st_nlink == 2
            assert os.stat('subdir/hardlink').st_nlink == 2
            assert open('subdir/hardlink', 'rb').read() == b'123456'
            assert os.stat('aaaa').st_nlink == 2
            assert os.stat('source2').st_nlink == 2
        with self.fuse_mount(self.repository_location + '::test', mountpoint, 'input/dir1', *ignore_perms), \
             changedir(mountpoint):
            assert os.stat('input/dir1/hardlink').st_nlink == 2
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 2
            assert open('input/dir1/subdir/hardlink', 'rb').read() == b'123456'
            assert os.stat('input/dir1/aaaa').st_nlink == 2
            assert os.stat('input/dir1/source2').st_nlink == 2
        with self.fuse_mount(self.repository_location + '::test', mountpoint, *ignore_perms), \
             changedir(mountpoint):
            assert os.stat('input/source').st_nlink == 4
            assert os.stat('input/abba').st_nlink == 4
            assert os.stat('input/dir1/hardlink').st_nlink == 4
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 4
            assert open('input/dir1/subdir/hardlink', 'rb').read() == b'123456'

    @requires_hardlinks
    def test_extract_hardlinks1(self):
        self._extract_hardlinks_setup()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            assert os.stat('input/source').st_nlink == 4
            assert os.stat('input/abba').st_nlink == 4
            assert os.stat('input/dir1/hardlink').st_nlink == 4
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 4
            assert open('input/dir1/subdir/hardlink', 'rb').read() == b'123456'

    @requires_hardlinks
    def test_extract_hardlinks2(self):
        self._extract_hardlinks_setup()
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', '--strip-components', '2')
            assert os.stat('hardlink').st_nlink == 2
            assert os.stat('subdir/hardlink').st_nlink == 2
            assert open('subdir/hardlink', 'rb').read() == b'123456'
            assert os.stat('aaaa').st_nlink == 2
            assert os.stat('source2').st_nlink == 2
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test', 'input/dir1')
            assert os.stat('input/dir1/hardlink').st_nlink == 2
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 2
            assert open('input/dir1/subdir/hardlink', 'rb').read() == b'123456'
            assert os.stat('input/dir1/aaaa').st_nlink == 2
            assert os.stat('input/dir1/source2').st_nlink == 2

    @requires_hardlinks
    def test_extract_hardlinks_twice(self):
        # setup for #5603
        path_a = os.path.join(self.input_path, 'a')
        path_b = os.path.join(self.input_path, 'b')
        os.mkdir(path_a)
        os.mkdir(path_b)
        hl_a = os.path.join(path_a, 'hardlink')
        hl_b = os.path.join(path_b, 'hardlink')
        self.create_regular_file(hl_a, contents=b'123456')
        os.link(hl_a, hl_b)
        self.cmd('init', '--encryption=none', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', 'input')  # give input twice!
        # now test extraction
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
            # if issue #5603 happens, extraction gives rc == 1 (triggering AssertionError) and warnings like:
            # input/a/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/a/hardlink'
            # input/b/hardlink: link: [Errno 2] No such file or directory: 'input/a/hardlink' -> 'input/b/hardlink'
            # otherwise, when fixed, the hardlinks should be there and have a link count of 2
            assert os.stat('input/a/hardlink').st_nlink == 2
            assert os.stat('input/b/hardlink').st_nlink == 2

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
        if are_hardlinks_supported():
            os.link('input/cache1/%s' % CACHE_TAG_NAME, 'input/cache3/%s' % CACHE_TAG_NAME)
        else:
            self.create_regular_file('cache3/%s' % CACHE_TAG_NAME,
                                     contents=CACHE_TAG_CONTENTS + b' extra stuff')

    def test_create_stdin(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        input_data = b'\x00foo\n\nbar\n   \n'
        self.cmd('create', self.repository_location + '::test', '-', input=input_data)
        item = json.loads(self.cmd('list', '--json-lines', self.repository_location + '::test'))
        assert item['uid'] == 0
        assert item['gid'] == 0
        assert item['size'] == len(input_data)
        assert item['path'] == 'stdin'
        extracted_data = self.cmd('extract', '--stdout', self.repository_location + '::test', binary_output=True)
        assert extracted_data == input_data

    def test_create_without_root(self):
        """test create without a root"""
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', exit_code=2)

    def test_create_pattern_root(self):
        """test create with only a root pattern"""
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        output = self.cmd('create', '-v', '--list', '--pattern=R input', self.repository_location + '::test')
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)

    def test_create_pattern(self):
        """test file patterns during create"""
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file_important', size=1024 * 80)
        output = self.cmd('create', '-v', '--list',
                          '--pattern=+input/file_important', '--pattern=-input/file*',
                          self.repository_location + '::test', 'input')
        self.assert_in("A input/file_important", output)
        self.assert_in('x input/file1', output)
        self.assert_in('x input/file2', output)

    def test_create_pattern_file(self):
        """test file patterns during create"""
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('otherfile', size=1024 * 80)
        self.create_regular_file('file_important', size=1024 * 80)
        output = self.cmd('create', '-v', '--list',
                          '--pattern=-input/otherfile', '--patterns-from=' + self.patterns_file_path,
                          self.repository_location + '::test', 'input')
        self.assert_in("A input/file_important", output)
        self.assert_in('x input/file1', output)
        self.assert_in('x input/file2', output)
        self.assert_in('x input/otherfile', output)

    def test_create_pattern_exclude_folder_but_recurse(self):
        """test when patterns exclude a parent folder, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, 'patterns2')
        with open(self.patterns_file_path2, 'wb') as fd:
            fd.write(b'+ input/x/b\n- input/x*\n')

        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('x/a/foo_a', size=1024 * 80)
        self.create_regular_file('x/b/foo_b', size=1024 * 80)
        self.create_regular_file('y/foo_y', size=1024 * 80)
        output = self.cmd('create', '-v', '--list',
                          '--patterns-from=' + self.patterns_file_path2,
                          self.repository_location + '::test', 'input')
        self.assert_in('x input/x/a/foo_a', output)
        self.assert_in("A input/x/b/foo_b", output)
        self.assert_in('A input/y/foo_y', output)

    def test_create_pattern_exclude_folder_no_recurse(self):
        """test when patterns exclude a parent folder and, but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, 'patterns2')
        with open(self.patterns_file_path2, 'wb') as fd:
            fd.write(b'+ input/x/b\n! input/x*\n')

        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('x/a/foo_a', size=1024 * 80)
        self.create_regular_file('x/b/foo_b', size=1024 * 80)
        self.create_regular_file('y/foo_y', size=1024 * 80)
        output = self.cmd('create', '-v', '--list',
                          '--patterns-from=' + self.patterns_file_path2,
                          self.repository_location + '::test', 'input')
        self.assert_not_in('input/x/a/foo_a', output)
        self.assert_not_in('input/x/a', output)
        self.assert_in('A input/y/foo_y', output)

    def test_create_pattern_intermediate_folders_first(self):
        """test that intermediate folders appear first when patterns exclude a parent folder but include a child"""
        self.patterns_file_path2 = os.path.join(self.tmpdir, 'patterns2')
        with open(self.patterns_file_path2, 'wb') as fd:
            fd.write(b'+ input/x/a\n+ input/x/b\n- input/x*\n')

        self.cmd('init', '--encryption=repokey', self.repository_location)

        self.create_regular_file('x/a/foo_a', size=1024 * 80)
        self.create_regular_file('x/b/foo_b', size=1024 * 80)
        with changedir('input'):
            self.cmd('create', '--patterns-from=' + self.patterns_file_path2,
                     self.repository_location + '::test', '.')

        # list the archive and verify that the "intermediate" folders appear before
        # their contents
        out = self.cmd('list', '--format', '{type} {path}{NL}', self.repository_location + '::test')
        out_list = out.splitlines()

        self.assert_in('d x/a', out_list)
        self.assert_in('d x/b', out_list)

        assert out_list.index('d x/a') < out_list.index('- x/a/foo_a')
        assert out_list.index('d x/b') < out_list.index('- x/b/foo_b')

    def test_create_no_cache_sync(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('delete', '--cache-only', self.repository_location)
        create_json = json.loads(self.cmd('create', '--no-cache-sync', self.repository_location + '::test', 'input',
                                          '--json', '--error'))  # ignore experimental warning
        info_json = json.loads(self.cmd('info', self.repository_location + '::test', '--json'))
        create_stats = create_json['cache']['stats']
        info_stats = info_json['cache']['stats']
        assert create_stats == info_stats
        self.cmd('delete', '--cache-only', self.repository_location)
        self.cmd('create', '--no-cache-sync', self.repository_location + '::test2', 'input')
        self.cmd('info', self.repository_location)
        self.cmd('check', self.repository_location)

    def test_extract_pattern_opt(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file_important', size=1024 * 80)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract',
                     '--pattern=+input/file_important', '--pattern=-input/file*',
                     self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file_important'])

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
        self.create_regular_file('tagged3/.NOBACKUP/file2', size=1024)

    def _assert_test_tagged(self):
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1'])

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
        self.create_regular_file('tagged2/.NOBACKUP2/subfile1', size=1024)
        self.create_regular_file('tagged2/file2', size=1024)
        self.create_regular_file('tagged3/%s' % CACHE_TAG_NAME,
                                 contents=CACHE_TAG_CONTENTS + b' extra stuff')
        self.create_regular_file('tagged3/file3', size=1024)
        self.create_regular_file('taggedall/.NOBACKUP1')
        self.create_regular_file('taggedall/.NOBACKUP2/subfile1', size=1024)
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

    def test_exclude_keep_tagged_deprecation(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output_warn = self.cmd('create', '--exclude-caches', '--keep-tag-files', self.repository_location + '::test', src_dir)
        self.assert_in('--keep-tag-files" has been deprecated.', output_warn)

    def test_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd('create', '--exclude-if-present', '.NOBACKUP1', '--exclude-if-present', '.NOBACKUP2',
                 '--exclude-caches', '--keep-exclude-tags', self.repository_location + '::test', 'input')
        self._assert_test_keep_tagged()

    def test_recreate_exclude_keep_tagged(self):
        self._create_test_keep_tagged()
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('recreate', '--exclude-if-present', '.NOBACKUP1', '--exclude-if-present', '.NOBACKUP2',
                 '--exclude-caches', '--keep-exclude-tags', self.repository_location + '::test')
        self._assert_test_keep_tagged()

    @pytest.mark.skipif(not are_hardlinks_supported(), reason='hardlinks not supported')
    def test_recreate_hardlinked_tags(self):  # test for issue #4911
        self.cmd('init', '--encryption=none', self.repository_location)
        self.create_regular_file('file1', contents=CACHE_TAG_CONTENTS)  # "wrong" filename, but correct tag contents
        os.mkdir(os.path.join(self.input_path, 'subdir'))  # to make sure the tag is encountered *after* file1
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'subdir', CACHE_TAG_NAME))  # correct tag name, hardlink to file1
        self.cmd('create', self.repository_location + '::test', 'input')
        # in the "test" archive, we now have, in this order:
        # - a regular file item for "file1"
        # - a hardlink item for "CACHEDIR.TAG" referring back to file1 for its contents
        self.cmd('recreate', '--exclude-caches', '--keep-exclude-tags', self.repository_location + '::test')
        # if issue #4911 is present, the recreate will crash with a KeyError for "input/file1"

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

    @pytest.mark.skipif(not xattr.XATTR_FAKEROOT, reason='xattr not supported on this system or on this version of'
                                                         'fakeroot')
    def test_extract_xattrs_errors(self):
        def patched_setxattr_E2BIG(*args, **kwargs):
            raise OSError(errno.E2BIG, 'E2BIG')

        def patched_setxattr_ENOTSUP(*args, **kwargs):
            raise OSError(errno.ENOTSUP, 'ENOTSUP')

        def patched_setxattr_EACCES(*args, **kwargs):
            raise OSError(errno.EACCES, 'EACCES')

        self.create_regular_file('file')
        xattr.setxattr('input/file', 'user.attribute', 'value')
        self.cmd('init', self.repository_location, '-e' 'none')
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            input_abspath = os.path.abspath('input/file')
            with patch.object(xattr, 'setxattr', patched_setxattr_E2BIG):
                out = self.cmd('extract', self.repository_location + '::test', exit_code=EXIT_WARNING)
                assert out == (input_abspath + ': when setting extended attribute user.attribute: too big for this filesystem\n')
            os.remove(input_abspath)
            with patch.object(xattr, 'setxattr', patched_setxattr_ENOTSUP):
                out = self.cmd('extract', self.repository_location + '::test', exit_code=EXIT_WARNING)
                assert out == (input_abspath + ': when setting extended attribute user.attribute: xattrs not supported on this filesystem\n')
            os.remove(input_abspath)
            with patch.object(xattr, 'setxattr', patched_setxattr_EACCES):
                out = self.cmd('extract', self.repository_location + '::test', exit_code=EXIT_WARNING)
                assert out == (input_abspath + ': when setting extended attribute user.attribute: Permission denied\n')
            assert os.path.isfile(input_abspath)

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
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
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

    def test_info_json(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        info_repo = json.loads(self.cmd('info', '--json', self.repository_location))
        repository = info_repo['repository']
        assert len(repository['id']) == 64
        assert 'last_modified' in repository
        assert datetime.strptime(repository['last_modified'], ISO_FORMAT)  # must not raise
        assert info_repo['encryption']['mode'] == 'repokey'
        assert 'keyfile' not in info_repo['encryption']
        cache = info_repo['cache']
        stats = cache['stats']
        assert all(isinstance(o, int) for o in stats.values())
        assert all(key in stats for key in ('total_chunks', 'total_csize', 'total_size', 'total_unique_chunks', 'unique_csize', 'unique_size'))

        info_archive = json.loads(self.cmd('info', '--json', self.repository_location + '::test'))
        assert info_repo['repository'] == info_archive['repository']
        assert info_repo['cache'] == info_archive['cache']
        archives = info_archive['archives']
        assert len(archives) == 1
        archive = archives[0]
        assert archive['name'] == 'test'
        assert isinstance(archive['command_line'], list)
        assert isinstance(archive['duration'], float)
        assert len(archive['id']) == 64
        assert 'stats' in archive
        assert datetime.strptime(archive['start'], ISO_FORMAT)
        assert datetime.strptime(archive['end'], ISO_FORMAT)

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

    def test_delete_multiple(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', 'input')
        self.cmd('create', self.repository_location + '::test2', 'input')
        self.cmd('create', self.repository_location + '::test3', 'input')
        self.cmd('delete', self.repository_location + '::test1', 'test2')
        self.cmd('extract', '--dry-run', self.repository_location + '::test3')
        self.cmd('delete', self.repository_location, 'test3')
        assert not self.cmd('list', self.repository_location)

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

    def test_delete_force(self):
        self.cmd('init', '--encryption=none', self.repository_location)
        self.create_src_archive('test')
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(repository, key, manifest, 'test')
            for item in archive.iter_items():
                if item.path.endswith('testsuite/archiver.py'):
                    repository.delete(item.chunks[-1].id)
                    break
            else:
                assert False  # missed the file
            repository.commit()
        output = self.cmd('delete', '--force', self.repository_location + '::test')
        self.assert_in('deleted archive was corrupted', output)
        self.cmd('check', '--repair', self.repository_location)
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('test', output)

    def test_delete_double_force(self):
        self.cmd('init', '--encryption=none', self.repository_location)
        self.create_src_archive('test')
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            archive = Archive(repository, key, manifest, 'test')
            id = archive.metadata.items[0]
            repository.put(id, b'corrupted items metadata stream chunk')
            repository.commit()
        self.cmd('delete', '--force', '--force', self.repository_location + '::test')
        self.cmd('check', '--repair', self.repository_location)
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('test', output)

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

    def test_readonly_check(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('check', '--verify-data', self.repository_location, exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('check', '--verify-data', self.repository_location)
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('check', '--verify-data', self.repository_location, '--bypass-lock')

    def test_readonly_diff(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('a')
        self.create_src_archive('b')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('diff', '%s::a' % self.repository_location, 'b', exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('diff', '%s::a' % self.repository_location, 'b')
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('diff', '%s::a' % self.repository_location, 'b', '--bypass-lock')

    def test_readonly_export_tar(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('export-tar', '%s::test' % self.repository_location, 'test.tar', exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('export-tar', '%s::test' % self.repository_location, 'test.tar')
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('export-tar', '%s::test' % self.repository_location, 'test.tar', '--bypass-lock')

    def test_readonly_extract(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('extract', '%s::test' % self.repository_location, exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('extract', '%s::test' % self.repository_location)
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('extract', '%s::test' % self.repository_location, '--bypass-lock')

    def test_readonly_info(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('info', self.repository_location, exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('info', self.repository_location)
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('info', self.repository_location, '--bypass-lock')

    def test_readonly_list(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd('list', self.repository_location, exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd('list', self.repository_location)
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd('list', self.repository_location, '--bypass-lock')

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_readonly_mount(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('test')
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                with self.fuse_mount(self.repository_location, exit_code=EXIT_ERROR):
                    pass
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    # self.fuse_mount always assumes fork=True, so for this test we have to manually set fork=False
                    with self.fuse_mount(self.repository_location, fork=False):
                        pass
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == 'LockFailed'
            # verify that command works with read-only repo when using --bypass-lock
            with self.fuse_mount(self.repository_location, None, '--bypass-lock'):
                pass

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
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        self.assert_equal(len(manifest.archives), 0)

    def add_unknown_feature(self, operation):
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            manifest.config[b'feature_flags'] = {operation.value.encode(): {b'mandatory': [b'unknown-feature']}}
            manifest.write()
            repository.commit()

    def cmd_raises_unknown_feature(self, args):
        if self.FORK_DEFAULT:
            self.cmd(*args, exit_code=EXIT_ERROR)
        else:
            with pytest.raises(MandatoryFeatureUnsupported) as excinfo:
                self.cmd(*args)
            assert excinfo.value.args == (['unknown-feature'],)

    def test_unknown_feature_on_create(self):
        print(self.cmd('init', '--encryption=repokey', self.repository_location))
        self.add_unknown_feature(Manifest.Operation.WRITE)
        self.cmd_raises_unknown_feature(['create', self.repository_location + '::test', 'input'])

    def test_unknown_feature_on_cache_sync(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('delete', '--cache-only', self.repository_location)
        self.add_unknown_feature(Manifest.Operation.READ)
        self.cmd_raises_unknown_feature(['create', self.repository_location + '::test', 'input'])

    def test_unknown_feature_on_change_passphrase(self):
        print(self.cmd('init', '--encryption=repokey', self.repository_location))
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature(['change-passphrase', self.repository_location])

    def test_unknown_feature_on_read(self):
        print(self.cmd('init', '--encryption=repokey', self.repository_location))
        self.cmd('create', self.repository_location + '::test', 'input')
        self.add_unknown_feature(Manifest.Operation.READ)
        with changedir('output'):
            self.cmd_raises_unknown_feature(['extract', self.repository_location + '::test'])

        self.cmd_raises_unknown_feature(['list', self.repository_location])
        self.cmd_raises_unknown_feature(['info', self.repository_location + '::test'])

    def test_unknown_feature_on_rename(self):
        print(self.cmd('init', '--encryption=repokey', self.repository_location))
        self.cmd('create', self.repository_location + '::test', 'input')
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature(['rename', self.repository_location + '::test', 'other'])

    def test_unknown_feature_on_delete(self):
        print(self.cmd('init', '--encryption=repokey', self.repository_location))
        self.cmd('create', self.repository_location + '::test', 'input')
        self.add_unknown_feature(Manifest.Operation.DELETE)
        # delete of an archive raises
        self.cmd_raises_unknown_feature(['delete', self.repository_location + '::test'])
        self.cmd_raises_unknown_feature(['prune', '--keep-daily=3', self.repository_location])
        # delete of the whole repository ignores features
        self.cmd('delete', self.repository_location)

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_unknown_feature_on_mount(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.add_unknown_feature(Manifest.Operation.READ)
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        os.mkdir(mountpoint)
        # XXX this might hang if it doesn't raise an error
        self.cmd_raises_unknown_feature(['mount', self.repository_location + '::test', mountpoint])

    @pytest.mark.allow_cache_wipe
    def test_unknown_mandatory_feature_in_cache(self):
        if self.prefix:
            path_prefix = 'ssh://__testsuite__'
        else:
            path_prefix = ''

        print(self.cmd('init', '--encryption=repokey', self.repository_location))

        with Repository(self.repository_path, exclusive=True) as repository:
            if path_prefix:
                repository._location = Location(self.repository_location)
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, key, manifest) as cache:
                cache.begin_txn()
                cache.cache_config.mandatory_features = set(['unknown-feature'])
                cache.commit()

        if self.FORK_DEFAULT:
            self.cmd('create', self.repository_location + '::test', 'input')
        else:
            called = False
            wipe_cache_safe = LocalCache.wipe_cache

            def wipe_wrapper(*args):
                nonlocal called
                called = True
                wipe_cache_safe(*args)

            with patch.object(LocalCache, 'wipe_cache', wipe_wrapper):
                self.cmd('create', self.repository_location + '::test', 'input')

            assert called

        with Repository(self.repository_path, exclusive=True) as repository:
            if path_prefix:
                repository._location = Location(self.repository_location)
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, key, manifest) as cache:
                assert cache.cache_config.mandatory_features == set([])

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
        self.create_regular_file('file1', size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
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

    def test_file_status_cs_cache_mode(self):
        """test that a changed file with faked "previous" mtime still gets backed up in ctime,size cache_mode"""
        self.create_regular_file('file1', contents=b'123')
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file('file2', size=10)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', '--files-cache=ctime,size', self.repository_location + '::test1', 'input')
        # modify file1, but cheat with the mtime (and atime) and also keep same size:
        st = os.stat('input/file1')
        self.create_regular_file('file1', contents=b'321')
        os.utime('input/file1', ns=(st.st_atime_ns, st.st_mtime_ns))
        # this mode uses ctime for change detection, so it should find file1 as modified
        output = self.cmd('create', '--list', '--files-cache=ctime,size', self.repository_location + '::test2', 'input')
        self.assert_in("M input/file1", output)

    def test_file_status_ms_cache_mode(self):
        """test that a chmod'ed file with no content changes does not get chunked again in mtime,size cache_mode"""
        self.create_regular_file('file1', size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file('file2', size=10)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', '--files-cache=mtime,size', self.repository_location + '::test1', 'input')
        # change mode of file1, no content change:
        st = os.stat('input/file1')
        os.chmod('input/file1', st.st_mode ^ stat.S_IRWXO)  # this triggers a ctime change, but mtime is unchanged
        # this mode uses mtime for change detection, so it should find file1 as unmodified
        output = self.cmd('create', '--list', '--files-cache=mtime,size', self.repository_location + '::test2', 'input')
        self.assert_in("U input/file1", output)

    def test_file_status_rc_cache_mode(self):
        """test that files get rechunked unconditionally in rechunk,ctime cache mode"""
        self.create_regular_file('file1', size=10)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file('file2', size=10)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', '--files-cache=rechunk,ctime', self.repository_location + '::test1', 'input')
        # no changes here, but this mode rechunks unconditionally
        output = self.cmd('create', '--list', '--files-cache=rechunk,ctime', self.repository_location + '::test2', 'input')
        self.assert_in("A input/file1", output)

    def test_file_status_excluded(self):
        """test that excluded paths are listed"""

        self.create_regular_file('file1', size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
        self.create_regular_file('file2', size=1024 * 80)
        if has_lchflags:
            self.create_regular_file('file3', size=1024 * 80)
            platform.set_flags(os.path.join(self.input_path, 'file3'), stat.UF_NODUMP)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('create', '--list', '--exclude-nodump', self.repository_location + '::test', 'input')
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)
        # should find second file as excluded
        output = self.cmd('create', '--list', '--exclude-nodump', self.repository_location + '::test1', 'input', '--exclude', '*/file2')
        self.assert_in("U input/file1", output)
        self.assert_in("x input/file2", output)
        if has_lchflags:
            self.assert_in("x input/file3", output)

    def test_create_json(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        create_info = json.loads(self.cmd('create', '--json', self.repository_location + '::test', 'input'))
        # The usual keys
        assert 'encryption' in create_info
        assert 'repository' in create_info
        assert 'cache' in create_info
        assert 'last_modified' in create_info['repository']

        archive = create_info['archive']
        assert archive['name'] == 'test'
        assert isinstance(archive['command_line'], list)
        assert isinstance(archive['duration'], float)
        assert len(archive['id']) == 64
        assert 'stats' in archive

    def test_create_topical(self):
        self.create_regular_file('file1', size=1024 * 80)
        time.sleep(1)  # file2 must have newer timestamps than file1
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
        os.symlink('somewhere does not exist', os.path.join(self.input_path, 'link'))
        self.cmd('init', '--encryption=repokey', self.repository_location)
        archive = self.repository_location + '::test'
        self.cmd('create', '--read-special', archive, 'input')
        output = self.cmd('list', archive)
        assert 'input/link -> somewhere does not exist' in output

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
        output = self.cmd('prune', '--list', '--dry-run', self.repository_location, '--keep-daily=2')
        self.assert_in('Keeping archive: test2', output)
        self.assert_in('Would prune:     test1', output)
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

    def test_prune_repository_glob(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::2015-08-12-10:00-foo', src_dir)
        self.cmd('create', self.repository_location + '::2015-08-12-20:00-foo', src_dir)
        self.cmd('create', self.repository_location + '::2015-08-12-10:00-bar', src_dir)
        self.cmd('create', self.repository_location + '::2015-08-12-20:00-bar', src_dir)
        output = self.cmd('prune', '--list', '--dry-run', self.repository_location, '--keep-daily=2', '--glob-archives=2015-*-foo')
        self.assert_in('Keeping archive: 2015-08-12-20:00-foo', output)
        self.assert_in('Would prune:     2015-08-12-10:00-foo', output)
        output = self.cmd('list', self.repository_location)
        self.assert_in('2015-08-12-10:00-foo', output)
        self.assert_in('2015-08-12-20:00-foo', output)
        self.assert_in('2015-08-12-10:00-bar', output)
        self.assert_in('2015-08-12-20:00-bar', output)
        self.cmd('prune', self.repository_location, '--keep-daily=2', '--glob-archives=2015-*-foo')
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('2015-08-12-10:00-foo', output)
        self.assert_in('2015-08-12-20:00-foo', output)
        self.assert_in('2015-08-12-10:00-bar', output)
        self.assert_in('2015-08-12-20:00-bar', output)

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
        output_2 = self.cmd('list', '--format', '{mode} {user:6} {group:6} {size:8d} {mtime} {path}{extra}{NEWLINE}', test_archive)
        output_3 = self.cmd('list', '--format', '{mtime:%s} {path}{NL}', test_archive)
        self.assertEqual(output_1, output_2)
        self.assertNotEqual(output_1, output_3)

    def test_list_repository_format(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', '--comment', 'comment 1', self.repository_location + '::test-1', src_dir)
        self.cmd('create', '--comment', 'comment 2', self.repository_location + '::test-2', src_dir)
        output_1 = self.cmd('list', self.repository_location)
        output_2 = self.cmd('list', '--format', '{archive:<36} {time} [{id}]{NL}', self.repository_location)
        self.assertEqual(output_1, output_2)
        output_1 = self.cmd('list', '--short', self.repository_location)
        self.assertEqual(output_1, 'test-1\ntest-2\n')
        output_1 = self.cmd('list', '--format', '{barchive}/', self.repository_location)
        self.assertEqual(output_1, 'test-1/test-2/')
        output_3 = self.cmd('list', '--format', '{name} {comment}{NL}', self.repository_location)
        self.assert_in('test-1 comment 1\n', output_3)
        self.assert_in('test-2 comment 2\n', output_3)

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
        output = self.cmd('list', '--format', '{size} {csize} {dsize} {dcsize} {path}{NL}', test_archive)
        size, csize, dsize, dcsize, path = output.split("\n")[1].split(" ")
        assert int(csize) < int(size)
        assert int(dcsize) < int(dsize)
        assert int(dsize) <= int(size)
        assert int(dcsize) <= int(csize)

    def test_list_json(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        list_repo = json.loads(self.cmd('list', '--json', self.repository_location))
        repository = list_repo['repository']
        assert len(repository['id']) == 64
        assert datetime.strptime(repository['last_modified'], ISO_FORMAT)  # must not raise
        assert list_repo['encryption']['mode'] == 'repokey'
        assert 'keyfile' not in list_repo['encryption']
        archive0 = list_repo['archives'][0]
        assert datetime.strptime(archive0['time'], ISO_FORMAT)  # must not raise

        list_archive = self.cmd('list', '--json-lines', self.repository_location + '::test')
        items = [json.loads(s) for s in list_archive.splitlines()]
        assert len(items) == 2
        file1 = items[1]
        assert file1['path'] == 'input/file1'
        assert file1['size'] == 81920
        assert datetime.strptime(file1['mtime'], ISO_FORMAT)  # must not raise

        list_archive = self.cmd('list', '--json-lines', '--format={sha256}', self.repository_location + '::test')
        items = [json.loads(s) for s in list_archive.splitlines()]
        assert len(items) == 2
        file1 = items[1]
        assert file1['path'] == 'input/file1'
        assert file1['sha256'] == 'b2915eb69f260d8d3c25249195f2c8f4f716ea82ec760ae929732c0262442b2b'

    def test_list_json_args(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('list', '--json-lines', self.repository_location, exit_code=2)
        self.cmd('list', '--json', self.repository_location + '::archive', exit_code=2)

    def test_log_json(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        log = self.cmd('create', '--log-json', self.repository_location + '::test', 'input', '--list', '--debug')
        messages = {}  # type -> message, one of each kind
        for line in log.splitlines():
            msg = json.loads(line)
            messages[msg['type']] = msg

        file_status = messages['file_status']
        assert 'status' in file_status
        assert file_status['path'].startswith('input')

        log_message = messages['log_message']
        assert isinstance(log_message['time'], float)
        assert log_message['levelname'] == 'DEBUG'  # there should only be DEBUG messages
        assert isinstance(log_message['message'], str)

    def test_debug_profile(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', '--debug-profile=create.prof')
        self.cmd('debug', 'convert-profile', 'create.prof', 'create.pyprof')
        stats = pstats.Stats('create.pyprof')
        stats.strip_dirs()
        stats.sort_stats('cumtime')

        self.cmd('create', self.repository_location + '::test2', 'input', '--debug-profile=create.pyprof')
        stats = pstats.Stats('create.pyprof')  # Only do this on trusted data!
        stats.strip_dirs()
        stats.sort_stats('cumtime')

    def test_common_options(self):
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        log = self.cmd('--debug', 'create', self.repository_location + '::test', 'input')
        assert 'security: read previous location' in log

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
        self.cmd()
        self.cmd('-h')

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
        self.cmd('create', '--exclude-nodump', self.repository_location + '::archive', 'input')
        self.cmd('create', '--exclude-nodump', self.repository_location + '::archive2', 'input')
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
            if are_hardlinks_supported():
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
                assert sti.st_size == len('somewhere')
                assert sto.st_size == len('somewhere')
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
                    assert sorted(no_selinux(xattr.listxattr(out_fn))) == ['user.empty', 'user.foo', ]
                    assert xattr.getxattr(out_fn, 'user.foo') == b'bar'
                    # Special case: getxattr returns None (not b'') when reading an empty xattr.
                    assert xattr.getxattr(out_fn, 'user.empty') is None
                else:
                    assert no_selinux(xattr.listxattr(out_fn)) == []
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
            self.create_regular_file('hardlink1', contents=b'123456')
            os.link('input/hardlink1', 'input/hardlink2')
            os.link('input/hardlink1', 'input/hardlink3')
        self.cmd('create', self.repository_location + '::archive1', 'input')
        self.create_regular_file('test', contents=b'second')
        self.cmd('create', self.repository_location + '::archive2', 'input')
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        # mount the whole repository, archive contents shall show up in versioned view:
        with self.fuse_mount(self.repository_location, mountpoint, '-o', 'versions'):
            path = os.path.join(mountpoint, 'input', 'test')  # filename shows up as directory ...
            files = os.listdir(path)
            assert all(f.startswith('test.') for f in files)  # ... with files test.xxxxx in there
            assert {b'first', b'second'} == {open(os.path.join(path, f), 'rb').read() for f in files}
            if are_hardlinks_supported():
                hl1 = os.path.join(mountpoint, 'input', 'hardlink1', 'hardlink1.00001')
                hl2 = os.path.join(mountpoint, 'input', 'hardlink2', 'hardlink2.00001')
                hl3 = os.path.join(mountpoint, 'input', 'hardlink3', 'hardlink3.00001')
                assert os.stat(hl1).st_ino == os.stat(hl2).st_ino == os.stat(hl3).st_ino
                assert open(hl3, 'rb').read() == b'123456'
        # similar again, but exclude the hardlink master:
        with self.fuse_mount(self.repository_location, mountpoint, '-o', 'versions', '-e', 'input/hardlink1'):
            if are_hardlinks_supported():
                hl2 = os.path.join(mountpoint, 'input', 'hardlink2', 'hardlink2.00001')
                hl3 = os.path.join(mountpoint, 'input', 'hardlink3', 'hardlink3.00001')
                assert os.stat(hl2).st_ino == os.stat(hl3).st_ino
                assert open(hl3, 'rb').read() == b'123456'

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
        assert len(output_dir) > 0 and output_dir[0].startswith('00000000_')
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

    def test_init_requires_encryption_option(self):
        self.cmd('init', self.repository_location, exit_code=2)

    def test_init_nested_repositories(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        if self.FORK_DEFAULT:
            self.cmd('init', '--encryption=repokey', self.repository_location + '/nested', exit_code=2)
        else:
            with pytest.raises(Repository.AlreadyExists):
                self.cmd('init', '--encryption=repokey', self.repository_location + '/nested')

    def check_cache(self):
        # First run a regular borg check
        self.cmd('check', self.repository_location)
        # Then check that the cache on disk matches exactly what's in the repo.
        with self.open_repository() as repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, key, manifest, sync=False) as cache:
                original_chunks = cache.chunks
            Cache.destroy(repository)
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
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
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
        self.cmd('create', self.repository_location + '::test2', 'input', '--files-cache=disabled')
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
        self.cmd('recreate', self.repository_location, '-C', 'lz4', '--recompress')
        self.check_cache()
        file_list = self.cmd('list', self.repository_location + '::test', 'input/compressible',
                             '--format', '{size} {csize} {sha256}')
        size, csize, sha256_after = file_list.split(' ')
        assert int(csize) < int(size)
        assert sha256_before == sha256_after

    def test_recreate_timestamp(self):
        local_timezone = datetime.now(timezone(timedelta(0))).astimezone().tzinfo
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        archive = self.repository_location + '::test0'
        self.cmd('create', archive, 'input')
        self.cmd('recreate', '--timestamp', "1970-01-02T00:00:00", '--comment',
                 'test', archive)
        info = self.cmd('info', archive).splitlines()
        dtime = datetime(1970, 1, 2) + local_timezone.utcoffset(None)
        s_time = dtime.strftime("%Y-%m-%d")
        assert any([re.search(r'Time \(start\).+ %s' % s_time, item) for item in info])
        assert any([re.search(r'Time \(end\).+ %s' % s_time, item) for item in info])

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

    def test_key_export_qr(self):
        export_file = self.output_path + '/exported.html'
        self.cmd('init', self.repository_location, '--encryption', 'repokey')
        repo_id = self._extract_repository_id(self.repository_path)
        self.cmd('key', 'export', '--qr-html', self.repository_location, export_file)

        with open(export_file, 'r', encoding='utf-8') as fd:
            export_contents = fd.read()

        assert bin_to_hex(repo_id) in export_contents
        assert export_contents.startswith('<!doctype html>')
        assert export_contents.endswith('</html>\n')

    def test_key_export_directory(self):
        export_directory = self.output_path + '/exported'
        os.mkdir(export_directory)

        self.cmd('init', self.repository_location, '--encryption', 'repokey')

        self.cmd('key', 'export', self.repository_location, export_directory, exit_code=EXIT_ERROR)

    def test_key_import_errors(self):
        export_file = self.output_path + '/exported'
        self.cmd('init', self.repository_location, '--encryption', 'keyfile')

        self.cmd('key', 'import', self.repository_location, export_file, exit_code=EXIT_ERROR)

        with open(export_file, 'w') as fd:
            fd.write('something not a key\n')

        if self.FORK_DEFAULT:
            self.cmd('key', 'import', self.repository_location, export_file, exit_code=2)
        else:
            with pytest.raises(NotABorgKeyFile):
                self.cmd('key', 'import', self.repository_location, export_file)

        with open(export_file, 'w') as fd:
            fd.write('BORG_KEY a0a0a0\n')

        if self.FORK_DEFAULT:
            self.cmd('key', 'import', self.repository_location, export_file, exit_code=2)
        else:
            with pytest.raises(RepoIdMismatch):
                self.cmd('key', 'import', self.repository_location, export_file)

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

    def test_key_import_paperkey(self):
        repo_id = 'e294423506da4e1ea76e8dcdf1a3919624ae3ae496fddf905610c351d3f09239'
        self.cmd('init', self.repository_location, '--encryption', 'keyfile')
        self._set_repository_id(self.repository_path, unhexlify(repo_id))

        key_file = self.keys_path + '/' + os.listdir(self.keys_path)[0]
        with open(key_file, 'w') as fd:
            fd.write(KeyfileKey.FILE_ID + ' ' + repo_id + '\n')
            fd.write(b2a_base64(b'abcdefghijklmnopqrstu').decode())

        typed_input = (
            b'2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41  02\n'   # Forgot to type "-"
            b'2 / e29442 3506da 4e1ea7  25f62a 5a3d41 - 02\n'   # Forgot to type second "/"
            b'2 / e29442 3506da 4e1ea7 / 25f62a 5a3d42 - 02\n'  # Typo (..42 not ..41)
            b'2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n'  # Correct! Congratulations
            b'616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n'
            b'\n\n'  # Abort [yN] => N
            b'737475 88\n'  # missing "-"
            b'73747i - 88\n'  # typo
            b'73747 - 88\n'  # missing nibble
            b'73 74 75  -  89\n'  # line checksum mismatch
            b'00a1 - 88\n'  # line hash collision - overall hash mismatch, have to start over

            b'2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n'
            b'616263 646566 676869 6a6b6c 6d6e6f 707172 - 6d\n'
            b'73 74 75  -  88\n'
        )

        # In case that this has to change, here is a quick way to find a colliding line hash:
        #
        # from hashlib import sha256
        # hash_fn = lambda x: sha256(b'\x00\x02' + x).hexdigest()[:2]
        # for i in range(1000):
        #     if hash_fn(i.to_bytes(2, byteorder='big')) == '88':  # 88 = line hash
        #         print(i.to_bytes(2, 'big'))
        #         break

        self.cmd('key', 'import', '--paper', self.repository_location, input=typed_input)

        # Test abort paths
        typed_input = b'\ny\n'
        self.cmd('key', 'import', '--paper', self.repository_location, input=typed_input)
        typed_input = b'2 / e29442 3506da 4e1ea7 / 25f62a 5a3d41 - 02\n\ny\n'
        self.cmd('key', 'import', '--paper', self.repository_location, input=typed_input)

    def test_debug_dump_manifest(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        dump_file = self.output_path + '/dump'
        output = self.cmd('debug', 'dump-manifest', self.repository_location, dump_file)
        assert output == ""
        with open(dump_file, "r") as f:
            result = json.load(f)
        assert 'archives' in result
        assert 'config' in result
        assert 'item_keys' in result
        assert 'timestamp' in result
        assert 'version' in result

    def test_debug_dump_archive(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        dump_file = self.output_path + '/dump'
        output = self.cmd('debug', 'dump-archive', self.repository_location + "::test", dump_file)
        assert output == ""
        with open(dump_file, "r") as f:
            result = json.load(f)
        assert '_name' in result
        assert '_manifest_entry' in result
        assert '_meta' in result
        assert '_items' in result

    def test_debug_refcount_obj(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('debug', 'refcount-obj', self.repository_location, '0' * 64).strip()
        assert output == 'object 0000000000000000000000000000000000000000000000000000000000000000 not found [info from chunks cache].'

        create_json = json.loads(self.cmd('create', '--json', self.repository_location + '::test', 'input'))
        archive_id = create_json['archive']['id']
        output = self.cmd('debug', 'refcount-obj', self.repository_location, archive_id).strip()
        assert output == 'object ' + archive_id + ' has 1 referrers [info from chunks cache].'

        # Invalid IDs do not abort or return an error
        output = self.cmd('debug', 'refcount-obj', self.repository_location, '124', 'xyza').strip()
        assert output == 'object id 124 is invalid.\nobject id xyza is invalid.'

    def test_debug_info(self):
        output = self.cmd('debug', 'info')
        assert 'CRC implementation' in output
        assert 'Python' in output

    def test_benchmark_crud(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        with environment_variable(_BORG_BENCHMARK_CRUD_TEST='YES'):
            self.cmd('benchmark', 'crud', self.repository_location, self.input_path)

    def test_config(self):
        self.create_test_files()
        os.unlink('input/flagfile')
        self.cmd('init', '--encryption=repokey', self.repository_location)
        output = self.cmd('config', '--list', self.repository_location)
        self.assert_in('[repository]', output)
        self.assert_in('version', output)
        self.assert_in('segments_per_dir', output)
        self.assert_in('storage_quota', output)
        self.assert_in('append_only', output)
        self.assert_in('additional_free_space', output)
        self.assert_in('id', output)
        for cfg_key, cfg_value in [
            ('additional_free_space', '2G'),
            ('repository.append_only', '1'),
        ]:
            output = self.cmd('config', self.repository_location, cfg_key)
            assert output == '0' + '\n'
            self.cmd('config', self.repository_location, cfg_key, cfg_value)
            output = self.cmd('config', self.repository_location, cfg_key)
            assert output == cfg_value + '\n'
            self.cmd('config', '--delete', self.repository_location, cfg_key)
            self.cmd('config', self.repository_location, cfg_key, exit_code=1)
        self.cmd('config', '--list', '--delete', self.repository_location, exit_code=2)
        self.cmd('config', self.repository_location, exit_code=2)
        self.cmd('config', self.repository_location, 'invalid-option', exit_code=1)

    requires_gnutar = pytest.mark.skipif(not have_gnutar(), reason='GNU tar must be installed for this test.')
    requires_gzip = pytest.mark.skipif(not shutil.which('gzip'), reason='gzip must be installed for this test.')

    @requires_gnutar
    def test_export_tar(self):
        self.create_test_files()
        os.unlink('input/flagfile')
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('export-tar', self.repository_location + '::test', 'simple.tar', '--progress')
        with changedir('output'):
            # This probably assumes GNU tar. Note -p switch to extract permissions regardless of umask.
            subprocess.check_call(['tar', 'xpf', '../simple.tar', '--warning=no-timestamp'])
        self.assert_dirs_equal('input', 'output/input', ignore_bsdflags=True, ignore_xattrs=True, ignore_ns=True)

    @requires_gnutar
    @requires_gzip
    def test_export_tar_gz(self):
        if not shutil.which('gzip'):
            pytest.skip('gzip is not installed')
        self.create_test_files()
        os.unlink('input/flagfile')
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        list = self.cmd('export-tar', self.repository_location + '::test', 'simple.tar.gz', '--list')
        assert 'input/file1\n' in list
        assert 'input/dir2\n' in list
        with changedir('output'):
            subprocess.check_call(['tar', 'xpf', '../simple.tar.gz', '--warning=no-timestamp'])
        self.assert_dirs_equal('input', 'output/input', ignore_bsdflags=True, ignore_xattrs=True, ignore_ns=True)

    @requires_gnutar
    def test_export_tar_strip_components(self):
        if not shutil.which('gzip'):
            pytest.skip('gzip is not installed')
        self.create_test_files()
        os.unlink('input/flagfile')
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        list = self.cmd('export-tar', self.repository_location + '::test', 'simple.tar', '--strip-components=1', '--list')
        # --list's path are those before processing with --strip-components
        assert 'input/file1\n' in list
        assert 'input/dir2\n' in list
        with changedir('output'):
            subprocess.check_call(['tar', 'xpf', '../simple.tar', '--warning=no-timestamp'])
        self.assert_dirs_equal('input', 'output/', ignore_bsdflags=True, ignore_xattrs=True, ignore_ns=True)

    @requires_hardlinks
    @requires_gnutar
    def test_export_tar_strip_components_links(self):
        self._extract_hardlinks_setup()
        self.cmd('export-tar', self.repository_location + '::test', 'output.tar', '--strip-components=2')
        with changedir('output'):
            subprocess.check_call(['tar', 'xpf', '../output.tar', '--warning=no-timestamp'])
            assert os.stat('hardlink').st_nlink == 2
            assert os.stat('subdir/hardlink').st_nlink == 2
            assert os.stat('aaaa').st_nlink == 2
            assert os.stat('source2').st_nlink == 2

    @requires_hardlinks
    @requires_gnutar
    def test_extract_hardlinks_tar(self):
        self._extract_hardlinks_setup()
        self.cmd('export-tar', self.repository_location + '::test', 'output.tar', 'input/dir1')
        with changedir('output'):
            subprocess.check_call(['tar', 'xpf', '../output.tar', '--warning=no-timestamp'])
            assert os.stat('input/dir1/hardlink').st_nlink == 2
            assert os.stat('input/dir1/subdir/hardlink').st_nlink == 2
            assert os.stat('input/dir1/aaaa').st_nlink == 2
            assert os.stat('input/dir1/source2').st_nlink == 2

    def test_detect_attic_repo(self):
        path = make_attic_repo(self.repository_path)
        cmds = [
            ['create', path + '::test', self.tmpdir],
            ['extract', path + '::test'],
            ['check', path],
            ['rename', path + '::test', 'newname'],
            ['list', path],
            ['delete', path],
            ['prune', path],
            ['info', path + '::test'],
            ['key', 'export', path, 'exported'],
            ['key', 'import', path, 'import'],
            ['change-passphrase', path],
            ['break-lock', path],
        ]
        for args in cmds:
            output = self.cmd(*args, fork=True, exit_code=2)
            assert 'Attic repository detected.' in output


@unittest.skipUnless('binary' in BORG_EXES, 'no borg.exe available')
class ArchiverTestCaseBinary(ArchiverTestCase):
    EXE = 'borg.exe'
    FORK_DEFAULT = True

    @unittest.skip('does not raise Exception, but sets rc==2')
    def test_init_parent_dirs(self):
        pass

    @unittest.skip('patches objects')
    def test_init_interrupt(self):
        pass

    @unittest.skip('patches objects')
    def test_extract_capabilities(self):
        pass

    @unittest.skip('patches objects')
    def test_extract_xattrs_errors(self):
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
                self.fail('should not happen')
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
                    self.fail('should not happen')
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
                    self.fail('should not happen')
        # list is also all-healthy again
        output = self.cmd('list', '--format={health}#{path}{LF}', self.repository_location + '::archive1', exit_code=0)
        self.assert_not_in('broken#', output)

    def test_missing_archive_item_chunk(self):
        archive, repository = self.open_archive('archive1')
        with repository:
            repository.delete(archive.metadata.items[0])
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
            repository.put(archive_id, key.encrypt(archive))
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
            def as_dict(self):
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
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, key, manifest) as cache:
                archive = Archive(repository, key, manifest, '0.13', cache=cache, create=True)
                archive.items_buffer.add(Attic013Item())
                archive.save()
        self.cmd('check', self.repository_location, exit_code=0)
        self.cmd('list', self.repository_location + '::0.13', exit_code=0)


class ManifestAuthenticationTest(ArchiverTestCaseBase):
    def spoof_manifest(self, repository):
        with repository:
            _, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            repository.put(Manifest.MANIFEST_ID, key.encrypt(msgpack.packb({
                'version': 1,
                'archives': {},
                'config': {},
                'timestamp': (datetime.utcnow() + timedelta(days=1)).strftime(ISO_FORMAT),
            })))
            repository.commit()

    def test_fresh_init_tam_required(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            repository.put(Manifest.MANIFEST_ID, key.encrypt(msgpack.packb({
                'version': 1,
                'archives': {},
                'timestamp': (datetime.utcnow() + timedelta(days=1)).strftime(ISO_FORMAT),
            })))
            repository.commit()

        with pytest.raises(TAMRequiredError):
            self.cmd('list', self.repository_location)

    def test_not_required(self):
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.create_src_archive('archive1234')
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            shutil.rmtree(get_security_dir(bin_to_hex(repository.id)))
            _, key = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            key.tam_required = False
            key.change_passphrase(key._passphrase)

            manifest = msgpack.unpackb(key.decrypt(None, repository.get(Manifest.MANIFEST_ID)))
            del manifest[b'tam']
            repository.put(Manifest.MANIFEST_ID, key.encrypt(msgpack.packb(manifest)))
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
            with pytest.raises(PathNotAllowed):
                self.cmd('init', '--encryption=repokey', self.repository_location + '_0')

        # restricted to a completely different path:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo']):
            with pytest.raises(PathNotAllowed):
                self.cmd('init', '--encryption=repokey', self.repository_location + '_1')
        path_prefix = os.path.dirname(self.repository_path)
        # restrict to repo directory's parent directory:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', path_prefix]):
            self.cmd('init', '--encryption=repokey', self.repository_location + '_2')
        # restrict to repo directory's parent directory and another directory:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo', '--restrict-to-path', path_prefix]):
            self.cmd('init', '--encryption=repokey', self.repository_location + '_3')

    def test_remote_repo_restrict_to_repository(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-repository', self.repository_path]):
            self.cmd('init', '--encryption=repokey', self.repository_location)
        parent_path = os.path.join(self.repository_path, '..')
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-repository', parent_path]):
            with pytest.raises(PathNotAllowed):
                self.cmd('init', '--encryption=repokey', self.repository_location)

    @unittest.skip('only works locally')
    def test_debug_put_get_delete_obj(self):
        pass

    @unittest.skip('only works locally')
    def test_config(self):
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


class ArchiverCorruptionTestCase(ArchiverTestCaseBase):
    def setUp(self):
        super().setUp()
        self.create_test_files()
        self.cmd('init', '--encryption=repokey', self.repository_location)
        self.cache_path = json.loads(self.cmd('info', self.repository_location, '--json'))['cache']['path']

    def corrupt(self, file, amount=1):
        with open(file, 'r+b') as fd:
            fd.seek(-amount, io.SEEK_END)
            corrupted = bytes(255-c for c in fd.read(amount))
            fd.seek(-amount, io.SEEK_END)
            fd.write(corrupted)

    def test_cache_chunks(self):
        self.corrupt(os.path.join(self.cache_path, 'chunks'))

        if self.FORK_DEFAULT:
            out = self.cmd('info', self.repository_location, exit_code=2)
            assert 'failed integrity check' in out
        else:
            with pytest.raises(FileIntegrityError):
                self.cmd('info', self.repository_location)

    def test_cache_files(self):
        self.cmd('create', self.repository_location + '::test', 'input')
        self.corrupt(os.path.join(self.cache_path, 'files'))
        out = self.cmd('create', self.repository_location + '::test1', 'input')
        # borg warns about the corrupt files cache, but then continues without files cache.
        assert 'files cache is corrupted' in out

    def test_chunks_archive(self):
        self.cmd('create', self.repository_location + '::test1', 'input')
        # Find ID of test1 so we can corrupt it later :)
        target_id = self.cmd('list', self.repository_location, '--format={id}{LF}').strip()
        self.cmd('create', self.repository_location + '::test2', 'input')

        # Force cache sync, creating archive chunks of test1 and test2 in chunks.archive.d
        self.cmd('delete', '--cache-only', self.repository_location)
        self.cmd('info', self.repository_location, '--json')

        chunks_archive = os.path.join(self.cache_path, 'chunks.archive.d')
        assert len(os.listdir(chunks_archive)) == 4  # two archives, one chunks cache and one .integrity file each

        self.corrupt(os.path.join(chunks_archive, target_id + '.compact'))

        # Trigger cache sync by changing the manifest ID in the cache config
        config_path = os.path.join(self.cache_path, 'config')
        config = ConfigParser(interpolation=None)
        config.read(config_path)
        config.set('cache', 'manifest', bin_to_hex(bytes(32)))
        with open(config_path, 'w') as fd:
            config.write(fd)

        # Cache sync notices corrupted archive chunks, but automatically recovers.
        out = self.cmd('create', '-v', self.repository_location + '::test3', 'input', exit_code=1)
        assert 'Reading cached archive chunk index for test1' in out
        assert 'Cached archive chunk index of test1 is corrupted' in out
        assert 'Fetching and building archive index for test1' in out

    def test_old_version_interfered(self):
        # Modify the main manifest ID without touching the manifest ID in the integrity section.
        # This happens if a version without integrity checking modifies the cache.
        config_path = os.path.join(self.cache_path, 'config')
        config = ConfigParser(interpolation=None)
        config.read(config_path)
        config.set('cache', 'manifest', bin_to_hex(bytes(32)))
        with open(config_path, 'w') as fd:
            config.write(fd)

        out = self.cmd('info', self.repository_location)
        assert 'Cache integrity data not available: old Borg version modified the cache.' in out


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
            os.link('input/file_replaced', 'input/hardlink_target_replaced')
            os.link('input/empty', 'input/hardlink_contents_changed')
            os.link('input/file_removed', 'input/hardlink_removed')
            os.link('input/file_removed2', 'input/hardlink_target_removed')

        # Create the first snapshot
        self.cmd('create', self.repository_location + '::test0', 'input')

        # Setup files for the second snapshot
        self.create_regular_file('file_added', size=2048)
        self.create_regular_file('file_empty_added', size=0)
        os.unlink('input/file_replaced')
        self.create_regular_file('file_replaced', contents=b'0' * 4096)
        os.unlink('input/file_removed')
        os.unlink('input/file_removed2')
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

        def do_asserts(output, can_compare_ids):
            # File contents changed (deleted and replaced with a new file)
            change = 'B' if can_compare_ids else '{:<19}'.format('modified')
            assert 'file_replaced' in output  # added to debug #3494
            assert '{} input/file_replaced'.format(change) in output

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
            change = '0 B' if can_compare_ids else '{:<19}'.format('modified')
            assert '{} input/empty'.format(change) in output
            if are_hardlinks_supported():
                assert '{} input/hardlink_contents_changed'.format(change) in output
            if are_symlinks_supported():
                assert 'input/link_target_contents_changed' not in output

            # Added a new file and a hard link to it. Both links to the same
            # inode should appear as separate files.
            assert 'added       2.05 kB input/file_added' in output
            if are_hardlinks_supported():
                assert 'added       2.05 kB input/hardlink_added' in output

            # check if a diff between non-existent and empty new file is found
            assert 'added           0 B input/file_empty_added' in output

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

        def do_json_asserts(output, can_compare_ids):
            def get_changes(filename, data):
                chgsets = [j['changes'] for j in data if j['path'] == filename]
                assert len(chgsets) < 2
                # return a flattened list of changes for given filename
                return [chg for chgset in chgsets for chg in chgset]

            # convert output to list of dicts
            joutput = [json.loads(line) for line in output.split('\n') if line]

            # File contents changed (deleted and replaced with a new file)
            expected = {'type': 'modified', 'added': 4096, 'removed': 1024} if can_compare_ids else {'type': 'modified'}
            assert expected in get_changes('input/file_replaced', joutput)

            # File unchanged
            assert not any(get_changes('input/file_unchanged', joutput))

            # Directory replaced with a regular file
            if 'BORG_TESTS_IGNORE_MODES' not in os.environ:
                assert {'type': 'mode', 'old_mode': 'drwxr-xr-x', 'new_mode': '-rwxr-xr-x'} in \
                    get_changes('input/dir_replaced_with_file', joutput)

            # Basic directory cases
            assert {'type': 'added directory'} in get_changes('input/dir_added', joutput)
            assert {'type': 'removed directory'} in get_changes('input/dir_removed', joutput)

            if are_symlinks_supported():
                # Basic symlink cases
                assert {'type': 'changed link'} in get_changes('input/link_changed', joutput)
                assert {'type': 'added link'} in get_changes('input/link_added', joutput)
                assert {'type': 'removed link'} in get_changes('input/link_removed', joutput)

                # Symlink replacing or being replaced
                assert any(chg['type'] == 'mode' and chg['new_mode'].startswith('l') for chg in
                    get_changes('input/dir_replaced_with_link', joutput))
                assert any(chg['type'] == 'mode' and chg['old_mode'].startswith('l') for chg in
                    get_changes('input/link_replaced_by_file', joutput))

                # Symlink target removed. Should not affect the symlink at all.
                assert not any(get_changes('input/link_target_removed', joutput))

            # The inode has two links and the file contents changed. Borg
            # should notice the changes in both links. However, the symlink
            # pointing to the file is not changed.
            expected = {'type': 'modified', 'added': 13, 'removed': 0} if can_compare_ids else {'type': 'modified'}
            assert expected in get_changes('input/empty', joutput)
            if are_hardlinks_supported():
                assert expected in get_changes('input/hardlink_contents_changed', joutput)
            if are_symlinks_supported():
                assert not any(get_changes('input/link_target_contents_changed', joutput))

            # Added a new file and a hard link to it. Both links to the same
            # inode should appear as separate files.
            assert {'type': 'added', 'size': 2048} in get_changes('input/file_added', joutput)
            if are_hardlinks_supported():
                assert {'type': 'added', 'size': 2048} in get_changes('input/hardlink_added', joutput)

            # check if a diff between non-existent and empty new file is found
            assert {'type': 'added', 'size': 0} in get_changes('input/file_empty_added', joutput)

            # The inode has two links and both of them are deleted. They should
            # appear as two deleted files.
            assert {'type': 'removed', 'size': 256} in get_changes('input/file_removed', joutput)
            if are_hardlinks_supported():
                assert {'type': 'removed', 'size': 256} in get_changes('input/hardlink_removed', joutput)

            # Another link (marked previously as the source in borg) to the
            # same inode was removed. This should not change this link at all.
            if are_hardlinks_supported():
                assert not any(get_changes('input/hardlink_target_removed', joutput))

            # Another link (marked previously as the source in borg) to the
            # same inode was replaced with a new regular file. This should not
            # change this link at all.
            if are_hardlinks_supported():
                assert not any(get_changes('input/hardlink_target_replaced', joutput))

        do_asserts(self.cmd('diff', self.repository_location + '::test0', 'test1a'), True)
        # We expect exit_code=1 due to the chunker params warning
        do_asserts(self.cmd('diff', self.repository_location + '::test0', 'test1b', exit_code=1), False)
        do_json_asserts(self.cmd('diff', self.repository_location + '::test0', 'test1a', '--json-lines'), True)

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
    # similar, but with --restrict-to-repository
    args = archiver.get_args(['borg', 'serve', '--restrict-to-repository=/r1', '--restrict-to-repository=/r2', ],
                             'borg serve --info --umask=0027')
    assert args.restrict_to_repositories == ['/r1', '/r2']
    # trying to cheat - break out of path restriction
    args = archiver.get_args(['borg', 'serve', '--restrict-to-path=/p1', '--restrict-to-path=/p2', ],
                             'borg serve --restrict-to-path=/')
    assert args.restrict_to_paths == ['/p1', '/p2']
    # trying to cheat - break out of repository restriction
    args = archiver.get_args(['borg', 'serve', '--restrict-to-repository=/r1', '--restrict-to-repository=/r2', ],
                             'borg serve --restrict-to-repository=/')
    assert args.restrict_to_repositories == ['/r1', '/r2']
    # trying to cheat - break below repository restriction
    args = archiver.get_args(['borg', 'serve', '--restrict-to-repository=/r1', '--restrict-to-repository=/r2', ],
                             'borg serve --restrict-to-repository=/r1/below')
    assert args.restrict_to_repositories == ['/r1', '/r2']
    # trying to cheat - try to execute different subcommand
    args = archiver.get_args(['borg', 'serve', '--restrict-to-path=/p1', '--restrict-to-path=/p2', ],
                             'borg init --encryption=repokey /')
    assert args.func == archiver.do_serve

    # Check that environment variables in the forced command don't cause issues. If the command
    # were not forced, environment variables would be interpreted by the shell, but this does not
    # happen for forced commands - we get the verbatim command line and need to deal with env vars.
    args = archiver.get_args(['borg', 'serve', ],
                             'BORG_HOSTNAME_IS_UNIQUE=yes borg serve --info')
    assert args.func == archiver.do_serve


def test_compare_chunk_contents():
    def ccc(a, b):
        chunks_a = [data for data in a]
        chunks_b = [data for data in b]
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
        matcher.add([parse_pattern('included')], IECommand.Include)
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


class TestCommonOptions:
    @staticmethod
    def define_common_options(add_common_option):
        add_common_option('-h', '--help', action='help', help='show this help message and exit')
        add_common_option('--critical', dest='log_level', help='foo',
                          action='store_const', const='critical', default='warning')
        add_common_option('--error', dest='log_level', help='foo',
                          action='store_const', const='error', default='warning')
        add_common_option('--append', dest='append', help='foo',
                          action='append', metavar='TOPIC', default=[])
        add_common_option('-p', '--progress', dest='progress', action='store_true', help='foo')
        add_common_option('--lock-wait', dest='lock_wait', type=int, metavar='N', default=1,
                          help='(default: %(default)d).')

    @pytest.fixture
    def basic_parser(self):
        parser = argparse.ArgumentParser(prog='test', description='test parser', add_help=False)
        parser.common_options = Archiver.CommonOptions(self.define_common_options,
                                                       suffix_precedence=('_level0', '_level1'))
        return parser

    @pytest.fixture
    def subparsers(self, basic_parser):
        return basic_parser.add_subparsers(title='required arguments', metavar='<command>')

    @pytest.fixture
    def parser(self, basic_parser):
        basic_parser.common_options.add_common_group(basic_parser, '_level0', provide_defaults=True)
        return basic_parser

    @pytest.fixture
    def common_parser(self, parser):
        common_parser = argparse.ArgumentParser(add_help=False, prog='test')
        parser.common_options.add_common_group(common_parser, '_level1')
        return common_parser

    @pytest.fixture
    def parse_vars_from_line(self, parser, subparsers, common_parser):
        subparser = subparsers.add_parser('subcommand', parents=[common_parser], add_help=False,
                                          description='foo', epilog='bar', help='baz',
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
        subparser.set_defaults(func=1234)
        subparser.add_argument('--append-only', dest='append_only', action='store_true')

        def parse_vars_from_line(*line):
            print(line)
            args = parser.parse_args(line)
            parser.common_options.resolve(args)
            return vars(args)

        return parse_vars_from_line

    def test_simple(self, parse_vars_from_line):
        assert parse_vars_from_line('--error') == {
            'append': [],
            'lock_wait': 1,
            'log_level': 'error',
            'progress': False
        }

        assert parse_vars_from_line('--error', 'subcommand', '--critical') == {
            'append': [],
            'lock_wait': 1,
            'log_level': 'critical',
            'progress': False,
            'append_only': False,
            'func': 1234,
        }

        with pytest.raises(SystemExit):
            parse_vars_from_line('--append-only', 'subcommand')

        assert parse_vars_from_line('--append=foo', '--append', 'bar', 'subcommand', '--append', 'baz') == {
            'append': ['foo', 'bar', 'baz'],
            'lock_wait': 1,
            'log_level': 'warning',
            'progress': False,
            'append_only': False,
            'func': 1234,
        }

    @pytest.mark.parametrize('position', ('before', 'after', 'both'))
    @pytest.mark.parametrize('flag,args_key,args_value', (
        ('-p', 'progress', True),
        ('--lock-wait=3', 'lock_wait', 3),
    ))
    def test_flag_position_independence(self, parse_vars_from_line, position, flag, args_key, args_value):
        line = []
        if position in ('before', 'both'):
            line.append(flag)
        line.append('subcommand')
        if position in ('after', 'both'):
            line.append(flag)

        result = {
            'append': [],
            'lock_wait': 1,
            'log_level': 'warning',
            'progress': False,
            'append_only': False,
            'func': 1234,
        }
        result[args_key] = args_value

        assert parse_vars_from_line(*line) == result


def test_parse_storage_quota():
    assert parse_storage_quota('50M') == 50 * 1000**2
    with pytest.raises(argparse.ArgumentTypeError):
        parse_storage_quota('5M')


def get_all_parsers():
    """
    Return dict mapping command to parser.
    """
    parser = Archiver(prog='borg').build_parser()
    borgfs_parser = Archiver(prog='borgfs').build_parser()
    parsers = {}

    def discover_level(prefix, parser, Archiver, extra_choices=None):
        choices = {}
        for action in parser._actions:
            if action.choices is not None and 'SubParsersAction' in str(action.__class__):
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            discover_level(command + " ", parser, Archiver)
            parsers[command] = parser

    discover_level("", parser, Archiver, {'borgfs': borgfs_parser})
    return parsers


@pytest.mark.parametrize('command, parser', list(get_all_parsers().items()))
def test_help_formatting(command, parser):
    if isinstance(parser.epilog, RstToTextLazy):
        assert parser.epilog.rst


@pytest.mark.parametrize('topic, helptext', list(Archiver.helptext.items()))
def test_help_formatting_helptexts(topic, helptext):
    assert str(rst_to_terminal(helptext))
