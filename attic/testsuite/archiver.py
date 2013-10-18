import os
from io import StringIO
import stat
import subprocess
import sys
import shutil
import tempfile
import time
import unittest
from hashlib import sha256
from attic import xattr
from attic.archiver import Archiver
from attic.repository import Repository
from attic.testsuite import AtticTestCase
from attic.crypto import bytes_to_long, num_aes_blocks

try:
    import llfuse
    has_llfuse = True
except ImportError:
    has_llfuse = False

src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__), '..', '..')


class changedir:
    def __init__(self, dir):
        self.dir = dir

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.dir)

    def __exit__(self, *args, **kw):
        os.chdir(self.old)


class ArchiverTestCase(AtticTestCase):

    prefix = ''

    def setUp(self):
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp()
        self.repository_path = os.path.join(self.tmpdir, 'repository')
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        self.keys_path = os.path.join(self.tmpdir, 'keys')
        self.cache_path = os.path.join(self.tmpdir, 'cache')
        os.environ['ATTIC_KEYS_DIR'] = self.keys_path
        os.environ['ATTIC_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        os.chdir(self._old_wd)

    def attic(self, *args, **kw):
        exit_code = kw.get('exit_code', 0)
        fork = kw.get('fork', False)
        if fork:
            try:
                output = subprocess.check_output((sys.executable, '-m', 'attic.archiver') + args)
                ret = 0
            except subprocess.CalledProcessError as e:
                output = e.output
                ret = e.returncode
            output = os.fsdecode(output)
            if ret != exit_code:
                print(output)
            self.assert_equal(exit_code, ret)
            return output
        args = list(args)
        stdout, stderr = sys.stdout, sys.stderr
        try:
            output = StringIO()
            sys.stdout = sys.stderr = output
            ret = self.archiver.run(args)
            sys.stdout, sys.stderr = stdout, stderr
            if ret != exit_code:
                print(output.getvalue())
            self.assert_equal(exit_code, ret)
            return output.getvalue()
        finally:
            sys.stdout, sys.stderr = stdout, stderr

    def create_src_archive(self, name):
        self.attic('create', self.repository_location + '::' + name, src_dir)

    def create_regual_file(self, name, size=0):
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
            fd.write(b'X' * size)

    def create_test_files(self):
        """Create a minimal test case including all supported file types
        """
        # File
        self.create_regual_file('file1', size=1024 * 80)
        # Directory
        self.create_regual_file('dir2/file2', size=1024 * 80)
        # File owner
        os.chown('input/file1', 100, 200)
        # File mode
        os.chmod('input/file1', 0o7755)
        os.chmod('input/dir2', 0o555)
        # Block device
        os.mknod('input/bdev', 0o600 | stat.S_IFBLK,  os.makedev(10, 20))
        # Char device
        os.mknod('input/cdev', 0o600 | stat.S_IFCHR,  os.makedev(30, 40))
        if xattr.is_enabled():
            xattr.setxattr(os.path.join(self.input_path, 'file1'), 'user.foo', b'bar')
        # Hard link
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'hardlink'))
        # Symlink
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        # FIFO node
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))

    def test_basic_functionality(self):
        self.create_test_files()
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        self.attic('create', self.repository_location + '::test.2', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test')
        self.assert_equal(len(self.attic('list', self.repository_location).splitlines()), 2)
        self.assert_equal(len(self.attic('list', self.repository_location + '::test').splitlines()), 9)
        self.assert_dirs_equal('input', 'output/input')
        info_output = self.attic('info', self.repository_location + '::test')
        shutil.rmtree(self.cache_path)
        info_output2 = self.attic('info', self.repository_location + '::test')
        # info_output2 starts with some "initializing cache" text but should
        # end the same way as info_output
        assert info_output2.endswith(info_output)

    def test_extract_include_exclude(self):
        self.attic('init', self.repository_location)
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('file2', size=1024 * 80)
        self.create_regual_file('file3', size=1024 * 80)
        self.create_regual_file('file4', size=1024 * 80)
        self.attic('create', '--exclude=input/file4', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test', 'input/file1', )
        self.assert_equal(sorted(os.listdir('output/input')), ['file1'])
        with changedir('output'):
            self.attic('extract', '--exclude=input/file2', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])

    def test_path_normalization(self):
        self.attic('init', self.repository_location)
        self.create_regual_file('dir1/dir2/file', size=1024 * 80)
        with changedir('input/dir1/dir2'):
            self.attic('create', self.repository_location + '::test', '../../../input/dir1/../dir1/dir2/..')
        output = self.attic('list', self.repository_location + '::test')
        self.assert_not_in('..', output)
        self.assert_in(' input/dir1/dir2/file', output)

    def test_overwrite(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        # Overwriting regular files and directories should be supported
        os.mkdir('output/input')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/dir2')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test')
        self.assert_dirs_equal('input', 'output/input')
        # But non-empty dirs should fail
        os.unlink('output/input/file1')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/file1/dir')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test', exit_code=1)

    def test_delete(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        self.attic('create', self.repository_location + '::test.2', 'input')
        self.attic('verify', self.repository_location + '::test')
        self.attic('verify', self.repository_location + '::test.2')
        self.attic('delete', self.repository_location + '::test')
        self.attic('verify', self.repository_location + '::test.2')
        self.attic('delete', self.repository_location + '::test.2')
        # Make sure all data except the manifest has been deleted
        repository = Repository(self.repository_path)
        self.assert_equal(repository._len(), 1)

    def test_corrupted_repository(self):
        self.attic('init', self.repository_location)
        self.create_src_archive('test')
        self.attic('verify', self.repository_location + '::test')
        name = sorted(os.listdir(os.path.join(self.tmpdir, 'repository', 'data', '0')), reverse=True)[0]
        fd = open(os.path.join(self.tmpdir, 'repository', 'data', '0', name), 'r+')
        fd.seek(100)
        fd.write('XXXX')
        fd.close()
        self.attic('verify', self.repository_location + '::test', exit_code=1)

    def test_readonly_repository(self):
        self.attic('init', self.repository_location)
        self.create_src_archive('test')
        os.system('chmod -R ugo-w ' + self.repository_path)
        try:
            self.attic('verify', self.repository_location + '::test')
        finally:
            # Restore permissions so shutil.rmtree is able to delete it
            os.system('chmod -R u+w ' + self.repository_path)

    def test_prune_repository(self):
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test1', src_dir)
        self.attic('create', self.repository_location + '::test2', src_dir)
        self.attic('prune', self.repository_location, '--daily=2')
        output = self.attic('list', self.repository_location)
        assert 'test1' not in output
        assert 'test2' in output

    def test_usage(self):
        self.assert_raises(SystemExit, lambda: self.attic())
        self.assert_raises(SystemExit, lambda: self.attic('-h'))

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_mount(self):
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        os.mkdir(mountpoint)
        self.attic('init', self.repository_location)
        self.create_test_files()
        self.attic('create', self.repository_location + '::archive', 'input')
        try:
            self.attic('mount', self.repository_location + '::archive', mountpoint, fork=True)
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
            for key, _ in repository.index.iteritems():
                data = repository.get(key)
                hash = sha256(data).digest()
                if not hash in seen:
                    seen.add(hash)
                    num_blocks = num_aes_blocks(len(data) - 41)
                    nonce = bytes_to_long(data[33:41])
                    for counter in range(nonce, nonce + num_blocks):
                        self.assert_not_in(counter, used)
                        used.add(counter)

        self.create_test_files()
        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
        self.attic('init', '--encryption=' + method, self.repository_location)
        verify_uniqueness()
        self.attic('create', self.repository_location + '::test', 'input')
        verify_uniqueness()
        self.attic('create', self.repository_location + '::test.2', 'input')
        verify_uniqueness()
        self.attic('delete', self.repository_location + '::test.2')
        verify_uniqueness()
        self.assert_equal(used, set(range(len(used))))

    def test_aes_counter_uniqueness_keyfile(self):
        self.verify_aes_counter_uniqueness('keyfile')

    def test_aes_counter_uniqueness_passphrase(self):
        self.verify_aes_counter_uniqueness('passphrase')



class RemoteArchiverTestCase(ArchiverTestCase):
    prefix = '__testsuite__:'
