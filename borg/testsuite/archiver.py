from binascii import hexlify
from configparser import ConfigParser
import errno
import os
from io import StringIO
import random
import stat
import subprocess
import sys
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch
from hashlib import sha256

import pytest

from .. import xattr
from ..archive import Archive, ChunkBuffer, CHUNK_MAX_EXP
from ..archiver import Archiver
from ..cache import Cache
from ..crypto import bytes_to_long, num_aes_blocks
from ..helpers import Manifest, EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR
from ..remote import RemoteRepository, PathNotAllowed
from ..repository import Repository
from . import BaseTestCase, changedir, environment_variable

try:
    import llfuse
    has_llfuse = True or llfuse  # avoids "unused import"
except ImportError:
    has_llfuse = False

has_lchflags = hasattr(os, 'lchflags')

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
        return ret, os.fsdecode(output)
    else:
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = StringIO()
            sys.stdout = sys.stderr = output = StringIO()
            if archiver is None:
                archiver = Archiver()
            args = archiver.parse_args(list(args))
            ret = archiver.run(args)
            return ret, output.getvalue()
        finally:
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr


# check if the binary "borg.exe" is available
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
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b'input/file2\n# A comment line, then a blank line\n\n')
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self._old_wd)
        shutil.rmtree(self.tmpdir)

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


class ArchiverTestCase(ArchiverTestCaseBase):

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
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'hardlink'))
        # Symlink
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        if xattr.is_enabled(self.input_path):
            xattr.setxattr(os.path.join(self.input_path, 'file1'), 'user.foo', b'bar')
            # XXX this always fails for me
            # ubuntu 14.04, on a TMP dir filesystem with user_xattr, using fakeroot
            # same for newer ubuntu and centos.
            # if this is supported just on specific platform, platform should be checked first,
            # so that the test setup for all tests using it does not fail here always for others.
            # xattr.setxattr(os.path.join(self.input_path, 'link1'), 'user.foo_symlink', b'bar_symlink', follow_symlinks=False)
        # FIFO node
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        if has_lchflags:
            os.lchflags(os.path.join(self.input_path, 'flagfile'), stat.UF_NODUMP)
        try:
            # Block device
            os.mknod('input/bdev', 0o600 | stat.S_IFBLK, os.makedev(10, 20))
            # Char device
            os.mknod('input/cdev', 0o600 | stat.S_IFCHR, os.makedev(30, 40))
            # File mode
            os.chmod('input/dir2', 0o555)  # if we take away write perms, we need root to remove contents
            # File owner
            os.chown('input/file1', 100, 200)
            have_root = True  # we have (fake)root
        except PermissionError:
            have_root = False
        return have_root

    def test_basic_functionality(self):
        have_root = self.create_test_files()
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', '--stats', self.repository_location + '::test.2', 'input')
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
            'input/fifo1',
            'input/file1',
            'input/flagfile',
            'input/hardlink',
            'input/link1',
        ]
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
        item_count = 3 if has_lchflags else 4  # one file is UF_NODUMP
        self.assert_in('Number of files: %d' % item_count, info_output)
        shutil.rmtree(self.cache_path)
        with environment_variable(BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK='yes'):
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

    def test_atime(self):
        self.create_test_files()
        atime, mtime = 123456780, 234567890
        os.utime('input/file1', (atime, mtime))
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        sti = os.stat('input/file1')
        sto = os.stat('output/input/file1')
        assert sti.st_mtime_ns == sto.st_mtime_ns == mtime * 1e9
        if hasattr(os, 'O_NOATIME'):
            assert sti.st_atime_ns == sto.st_atime_ns == atime * 1e9
        else:
            # it touched the input file's atime while backing it up
            assert sto.st_atime_ns == atime * 1e9

    def _extract_repository_id(self, path):
        return Repository(self.repository_path).id

    def _set_repository_id(self, path, id):
        config = ConfigParser(interpolation=None)
        config.read(os.path.join(path, 'config'))
        config.set('repository', 'id', hexlify(id).decode('ascii'))
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)
        return Repository(self.repository_path).id

    def test_sparse_file(self):
        # no sparse file support on Mac OS X
        sparse_support = sys.platform != 'darwin'
        filename = os.path.join(self.input_path, 'sparse')
        content = b'foobar'
        hole_size = 5 * (1 << CHUNK_MAX_EXP)  # 5 full chunker buffers
        with open(filename, 'wb') as fd:
            # create a file that has a hole at the beginning and end (if the
            # OS and filesystem supports sparse files)
            fd.seek(hole_size, 1)
            fd.write(content)
            fd.seek(hole_size, 1)
            pos = fd.tell()
            fd.truncate(pos)
        total_len = hole_size + len(content) + hole_size
        st = os.stat(filename)
        self.assert_equal(st.st_size, total_len)
        if sparse_support and hasattr(st, 'st_blocks'):
            self.assert_true(st.st_blocks * 512 < total_len / 9)  # is input sparse?
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', '--sparse', self.repository_location + '::test')
        self.assert_dirs_equal('input', 'output/input')
        filename = os.path.join(self.output_path, 'input', 'sparse')
        with open(filename, 'rb') as fd:
            # check if file contents are as expected
            self.assert_equal(fd.read(hole_size), b'\0' * hole_size)
            self.assert_equal(fd.read(len(content)), content)
            self.assert_equal(fd.read(hole_size), b'\0' * hole_size)
        st = os.stat(filename)
        self.assert_equal(st.st_size, total_len)
        if sparse_support and hasattr(st, 'st_blocks'):
            self.assert_true(st.st_blocks * 512 < total_len / 9)  # is output sparse?

    def test_unusual_filenames(self):
        filenames = ['normal', 'with some blanks', '(with_parens)', ]
        for filename in filenames:
            filename = os.path.join(self.input_path, filename)
            with open(filename, 'wb'):
                pass
        self.cmd('init', self.repository_location)
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

    def test_strip_components(self):
        self.cmd('init', self.repository_location)
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

    def test_extract_include_exclude(self):
        self.cmd('init', self.repository_location)
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
        self.cmd('init', self.repository_location)
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
        self.cmd('init', self.repository_location)
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
        self.cmd("init", self.repository_location)
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

    def test_exclude_caches(self):
        self.cmd('init', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('cache1/CACHEDIR.TAG', contents=b'Signature: 8a477f597d28d172789f06886806bc55 extra stuff')
        self.create_regular_file('cache2/CACHEDIR.TAG', contents=b'invalid signature')
        self.cmd('create', '--exclude-caches', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['cache2', 'file1'])
        self.assert_equal(sorted(os.listdir('output/input/cache2')), ['CACHEDIR.TAG'])

    def test_exclude_tagged(self):
        self.cmd('init', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('tagged1/.NOBACKUP')
        self.create_regular_file('tagged2/00-NOBACKUP')
        self.create_regular_file('tagged3/.NOBACKUP/file2')
        self.cmd('create', '--exclude-if-present', '.NOBACKUP', '--exclude-if-present', '00-NOBACKUP', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'tagged3'])

    def test_exclude_keep_tagged(self):
        self.cmd('init', self.repository_location)
        self.create_regular_file('file0', size=1024)
        self.create_regular_file('tagged1/.NOBACKUP1')
        self.create_regular_file('tagged1/file1', size=1024)
        self.create_regular_file('tagged2/.NOBACKUP2')
        self.create_regular_file('tagged2/file2', size=1024)
        self.create_regular_file('tagged3/CACHEDIR.TAG', contents=b'Signature: 8a477f597d28d172789f06886806bc55 extra stuff')
        self.create_regular_file('tagged3/file3', size=1024)
        self.create_regular_file('taggedall/.NOBACKUP1')
        self.create_regular_file('taggedall/.NOBACKUP2')
        self.create_regular_file('taggedall/CACHEDIR.TAG', contents=b'Signature: 8a477f597d28d172789f06886806bc55 extra stuff')
        self.create_regular_file('taggedall/file4', size=1024)
        self.cmd('create', '--exclude-if-present', '.NOBACKUP1', '--exclude-if-present', '.NOBACKUP2',
                 '--exclude-caches', '--keep-tag-files', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.cmd('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file0', 'tagged1', 'tagged2', 'tagged3', 'taggedall'])
        self.assert_equal(os.listdir('output/input/tagged1'), ['.NOBACKUP1'])
        self.assert_equal(os.listdir('output/input/tagged2'), ['.NOBACKUP2'])
        self.assert_equal(os.listdir('output/input/tagged3'), ['CACHEDIR.TAG'])
        self.assert_equal(sorted(os.listdir('output/input/taggedall')),
                          ['.NOBACKUP1', '.NOBACKUP2', 'CACHEDIR.TAG', ])

    def test_path_normalization(self):
        self.cmd('init', self.repository_location)
        self.create_regular_file('dir1/dir2/file', size=1024 * 80)
        with changedir('input/dir1/dir2'):
            self.cmd('create', self.repository_location + '::test', '../../../input/dir1/../dir1/dir2/..')
        output = self.cmd('list', self.repository_location + '::test')
        self.assert_not_in('..', output)
        self.assert_in(' input/dir1/dir2/file', output)

    def test_exclude_normalization(self):
        self.cmd('init', self.repository_location)
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
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input', 'input')

    def test_overwrite(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', self.repository_location)
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
        self.cmd('init', self.repository_location)
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
        repository = Repository(self.repository_path)
        manifest, key = Manifest.load(repository)
        self.assert_equal(len(manifest.archives), 2)
        self.assert_in('test.3', manifest.archives)
        self.assert_in('test.4', manifest.archives)

    def test_delete(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', self.repository_location + '::test.2', 'input')
        self.cmd('extract', '--dry-run', self.repository_location + '::test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        self.cmd('delete', self.repository_location + '::test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test.2')
        self.cmd('delete', '--stats', self.repository_location + '::test.2')
        # Make sure all data except the manifest has been deleted
        repository = Repository(self.repository_path)
        self.assert_equal(len(repository), 1)

    def test_delete_repo(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        self.cmd('create', self.repository_location + '::test.2', 'input')
        self.cmd('delete', self.repository_location)
        # Make sure the repo is gone
        self.assertFalse(os.path.exists(self.repository_path))

    def test_corrupted_repository(self):
        self.cmd('init', self.repository_location)
        self.create_src_archive('test')
        self.cmd('extract', '--dry-run', self.repository_location + '::test')
        self.cmd('check', self.repository_location)
        name = sorted(os.listdir(os.path.join(self.tmpdir, 'repository', 'data', '0')), reverse=True)[0]
        with open(os.path.join(self.tmpdir, 'repository', 'data', '0', name), 'r+b') as fd:
            fd.seek(100)
            fd.write(b'XXXX')
        self.cmd('check', self.repository_location, exit_code=1)

    # we currently need to be able to create a lock directory inside the repo:
    @pytest.mark.xfail(reason="we need to be able to create the lock directory inside the repo")
    def test_readonly_repository(self):
        self.cmd('init', self.repository_location)
        self.create_src_archive('test')
        os.system('chmod -R ugo-w ' + self.repository_path)
        try:
            self.cmd('extract', '--dry-run', self.repository_location + '::test')
        finally:
            # Restore permissions so shutil.rmtree is able to delete it
            os.system('chmod -R u+w ' + self.repository_path)

    def test_umask(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        mode = os.stat(self.repository_path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_create_dry_run(self):
        self.cmd('init', self.repository_location)
        self.cmd('create', '--dry-run', self.repository_location + '::test', 'input')
        # Make sure no archive has been created
        repository = Repository(self.repository_path)
        manifest, key = Manifest.load(repository)
        self.assert_equal(len(manifest.archives), 0)

    def test_progress(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.cmd('init', self.repository_location)
        # progress forced on
        output = self.cmd('create', '--progress', self.repository_location + '::test4', 'input')
        self.assert_in("\r", output)
        # progress forced off
        output = self.cmd('create', self.repository_location + '::test5', 'input')
        self.assert_not_in("\r", output)

    def test_file_status(self):
        """test that various file status show expected results

        clearly incomplete: only tests for the weird "unchanged" status for now"""
        now = time.time()
        self.create_regular_file('file1', size=1024 * 80)
        os.utime('input/file1', (now - 5, now - 5))  # 5 seconds ago
        self.create_regular_file('file2', size=1024 * 80)
        self.cmd('init', self.repository_location)
        output = self.cmd('create', '-v', '--list', self.repository_location + '::test', 'input')
        self.assert_in("A input/file1", output)
        self.assert_in("A input/file2", output)
        # should find first file as unmodified
        output = self.cmd('create', '-v', '--list', self.repository_location + '::test1', 'input')
        self.assert_in("U input/file1", output)
        # this is expected, although surprising, for why, see:
        # https://borgbackup.readthedocs.org/en/latest/faq.html#i-am-seeing-a-added-status-for-a-unchanged-file
        self.assert_in("A input/file2", output)

    def test_create_topical(self):
        now = time.time()
        self.create_regular_file('file1', size=1024 * 80)
        os.utime('input/file1', (now-5, now-5))
        self.create_regular_file('file2', size=1024 * 80)
        self.cmd('init', self.repository_location)
        # no listing by default
        output = self.cmd('create', self.repository_location + '::test', 'input')
        self.assert_not_in('file1', output)
        # shouldn't be listed even if unchanged
        output = self.cmd('create', self.repository_location + '::test0', 'input')
        self.assert_not_in('file1', output)
        # should list the file as unchanged
        output = self.cmd('create', '-v', '--list', '--filter=U', self.repository_location + '::test1', 'input')
        self.assert_in('file1', output)
        # should *not* list the file as changed
        output = self.cmd('create', '-v', '--filter=AM', self.repository_location + '::test2', 'input')
        self.assert_not_in('file1', output)
        # change the file
        self.create_regular_file('file1', size=1024 * 100)
        # should list the file as changed
        output = self.cmd('create', '-v', '--list', '--filter=AM', self.repository_location + '::test3', 'input')
        self.assert_in('file1', output)

    # def test_cmdline_compatibility(self):
    #    self.create_regular_file('file1', size=1024 * 80)
    #    self.cmd('init', self.repository_location)
    #    self.cmd('create', self.repository_location + '::test', 'input')
    #    output = self.cmd('foo', self.repository_location, '--old')
    #    self.assert_in('"--old" has been deprecated. Use "--new" instead', output)

    def test_prune_repository(self):
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', src_dir)
        self.cmd('create', self.repository_location + '::test2', src_dir)
        output = self.cmd('prune', '-v', '--list', '--dry-run', self.repository_location, '--keep-daily=2')
        self.assert_in('Keeping archive: test2', output)
        self.assert_in('Would prune:     test1', output)
        output = self.cmd('list', self.repository_location)
        self.assert_in('test1', output)
        self.assert_in('test2', output)
        self.cmd('prune', self.repository_location, '--keep-daily=2')
        output = self.cmd('list', self.repository_location)
        self.assert_not_in('test1', output)
        self.assert_in('test2', output)

    def test_prune_repository_save_space(self):
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test1', src_dir)
        self.cmd('create', self.repository_location + '::test2', src_dir)
        output = self.cmd('prune', '-v', '--list', '--dry-run', self.repository_location, '--keep-daily=2')
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
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::foo-2015-08-12-10:00', src_dir)
        self.cmd('create', self.repository_location + '::foo-2015-08-12-20:00', src_dir)
        self.cmd('create', self.repository_location + '::bar-2015-08-12-10:00', src_dir)
        self.cmd('create', self.repository_location + '::bar-2015-08-12-20:00', src_dir)
        output = self.cmd('prune', '-v', '--list', '--dry-run', self.repository_location, '--keep-daily=2', '--prefix=foo-')
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
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test-1', src_dir)
        self.cmd('create', self.repository_location + '::something-else-than-test-1', src_dir)
        self.cmd('create', self.repository_location + '::test-2', src_dir)
        output = self.cmd('list', '--prefix=test-', self.repository_location)
        self.assert_in('test-1', output)
        self.assert_in('test-2', output)
        self.assert_not_in('something-else', output)

    def test_list_list_format(self):
        self.cmd('init', self.repository_location)
        test_archive = self.repository_location + '::test'
        self.cmd('create', test_archive, src_dir)
        output_1 = self.cmd('list', test_archive)
        output_2 = self.cmd('list', '--list-format', '{mode} {user:6} {group:6} {size:8d} {isomtime} {path}{extra}{NEWLINE}', test_archive)
        output_3 = self.cmd('list', '--list-format', '{mtime:%s} {path}{NL}', test_archive)
        self.assertEqual(output_1, output_2)
        self.assertNotEqual(output_1, output_3)

    def test_break_lock(self):
        self.cmd('init', self.repository_location)
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
    def test_fuse_mount_repository(self):
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        os.mkdir(mountpoint)
        self.cmd('init', self.repository_location)
        self.create_test_files()
        self.cmd('create', self.repository_location + '::archive', 'input')
        self.cmd('create', self.repository_location + '::archive2', 'input')
        try:
            self.cmd('mount', self.repository_location, mountpoint, fork=True)
            self.wait_for_mount(mountpoint)
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'archive', 'input'))
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'archive2', 'input'))
        finally:
            if sys.platform.startswith('linux'):
                os.system('fusermount -u ' + mountpoint)
            else:
                os.system('umount ' + mountpoint)
            os.rmdir(mountpoint)
            # Give the daemon some time to exit
            time.sleep(.2)

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_mount_archive(self):
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        os.mkdir(mountpoint)
        self.cmd('init', self.repository_location)
        self.create_test_files()
        self.cmd('create', self.repository_location + '::archive', 'input')
        try:
            self.cmd('mount', self.repository_location + '::archive', mountpoint, fork=True)
            self.wait_for_mount(mountpoint)
            self.assert_dirs_equal(self.input_path, os.path.join(mountpoint, 'input'))
        finally:
            if sys.platform.startswith('linux'):
                os.system('fusermount -u ' + mountpoint)
            else:
                os.system('umount ' + mountpoint)
            os.rmdir(mountpoint)
            # Give the daemon some time to exit
            time.sleep(.2)

    def verify_aes_counter_uniqueness(self, method):
        seen = set()  # Chunks already seen
        used = set()  # counter values already used

        def verify_uniqueness():
            repository = Repository(self.repository_path)
            for key, _ in repository.open_index(repository.get_transaction_id()).iteritems():
                data = repository.get(key)
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
        self.assert_equal(used, set(range(len(used))))

    def test_aes_counter_uniqueness_keyfile(self):
        self.verify_aes_counter_uniqueness('keyfile')

    def test_aes_counter_uniqueness_passphrase(self):
        self.verify_aes_counter_uniqueness('repokey')

    def test_debug_dump_archive_items(self):
        self.create_test_files()
        self.cmd('init', self.repository_location)
        self.cmd('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            output = self.cmd('debug-dump-archive-items', self.repository_location + '::test')
        output_dir = sorted(os.listdir('output'))
        assert len(output_dir) > 0 and output_dir[0].startswith('000000_')
        assert 'Done.' in output

    def test_debug_put_get_delete_obj(self):
        self.cmd('init', self.repository_location)
        data = b'some data'
        hexkey = sha256(data).hexdigest()
        self.create_regular_file('file', contents=data)
        output = self.cmd('debug-put-obj', self.repository_location, 'input/file')
        assert hexkey in output
        output = self.cmd('debug-get-obj', self.repository_location, hexkey, 'output/file')
        assert hexkey in output
        with open('output/file', 'rb') as f:
            data_read = f.read()
        assert data == data_read
        output = self.cmd('debug-delete-obj', self.repository_location, hexkey)
        assert "deleted" in output
        output = self.cmd('debug-delete-obj', self.repository_location, hexkey)
        assert "not found" in output
        output = self.cmd('debug-delete-obj', self.repository_location, 'invalid')
        assert "is invalid" in output


@unittest.skipUnless('binary' in BORG_EXES, 'no borg.exe available')
class ArchiverTestCaseBinary(ArchiverTestCase):
    EXE = 'borg.exe'
    FORK_DEFAULT = True


class ArchiverCheckTestCase(ArchiverTestCaseBase):

    def setUp(self):
        super().setUp()
        with patch.object(ChunkBuffer, 'BUFFER_SIZE', 10):
            self.cmd('init', self.repository_location)
            self.create_src_archive('archive1')
            self.create_src_archive('archive2')

    def open_archive(self, name):
        repository = Repository(self.repository_path)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, name)
        return archive, repository

    def test_check_usage(self):
        output = self.cmd('check', '-v', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)
        output = self.cmd('check', '-v', '--repository-only', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_not_in('Starting archive consistency check', output)
        output = self.cmd('check', '-v', '--archives-only', self.repository_location, exit_code=0)
        self.assert_not_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)
        output = self.cmd('check', '-v', '--archives-only', '--prefix=archive2', self.repository_location, exit_code=0)
        self.assert_not_in('archive1', output)

    def test_missing_file_chunk(self):
        archive, repository = self.open_archive('archive1')
        for item in archive.iter_items():
            if item[b'path'].endswith('testsuite/archiver.py'):
                repository.delete(item[b'chunks'][-1][0])
                break
        repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_missing_archive_item_chunk(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(archive.metadata[b'items'][-5])
        repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_missing_archive_metadata(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(archive.id)
        repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_missing_manifest(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(Manifest.MANIFEST_ID)
        repository.commit()
        self.cmd('check', self.repository_location, exit_code=1)
        output = self.cmd('check', '-v', '--repair', self.repository_location, exit_code=0)
        self.assert_in('archive1', output)
        self.assert_in('archive2', output)
        self.cmd('check', self.repository_location, exit_code=0)

    def test_extra_chunks(self):
        self.cmd('check', self.repository_location, exit_code=0)
        repository = Repository(self.repository_location)
        repository.put(b'01234567890123456789012345678901', b'xxxx')
        repository.commit()
        repository.close()
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', self.repository_location, exit_code=1)
        self.cmd('check', '--repair', self.repository_location, exit_code=0)
        self.cmd('check', self.repository_location, exit_code=0)
        self.cmd('extract', '--dry-run', self.repository_location + '::archive1', exit_code=0)


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

    # skip fuse tests here, they deadlock since this change in exec_cmd:
    # -output = subprocess.check_output(borg + args, stderr=None)
    # +output = subprocess.check_output(borg + args, stderr=subprocess.STDOUT)
    # this was introduced because some tests expect stderr contents to show up
    # in "output" also. Also, the non-forking exec_cmd catches both, too.
    @unittest.skip('deadlock issues')
    def test_fuse_mount_repository(self):
        pass

    @unittest.skip('deadlock issues')
    def test_fuse_mount_archive(self):
        pass

    @unittest.skip('only works locally')
    def test_debug_put_get_delete_obj(self):
        pass


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
