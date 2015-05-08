from binascii import hexlify
from configparser import RawConfigParser
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
from attic.archive import Archive, ChunkBuffer
from attic.archiver import Archiver
from attic.cache import Cache
from attic.crypto import bytes_to_long, num_aes_blocks
from attic.helpers import Manifest
from attic.remote import RemoteRepository, PathNotAllowed
from attic.repository import Repository
from attic.testsuite import AtticTestCase
from attic.testsuite.mock import patch

try:
    import llfuse
    has_llfuse = True
except ImportError:
    has_llfuse = False

has_lchflags = hasattr(os, 'lchflags')

src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__), '..')


class changedir:
    def __init__(self, dir):
        self.dir = dir

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.dir)

    def __exit__(self, *args, **kw):
        os.chdir(self.old)


class environment_variable:
    def __init__(self, **values):
        self.values = values
        self.old_values = {}

    def __enter__(self):
        for k, v in self.values.items():
            self.old_values[k] = os.environ.get(k)
            os.environ[k] = v

    def __exit__(self, *args, **kw):
        for k, v in self.old_values.items():
            if v is not None:
                os.environ[k] = v


class ArchiverTestCaseBase(AtticTestCase):

    prefix = ''

    def setUp(self):
        os.environ['ATTIC_CHECK_I_KNOW_WHAT_I_AM_DOING'] = '1'
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp()
        self.repository_path = os.path.join(self.tmpdir, 'repository')
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        self.keys_path = os.path.join(self.tmpdir, 'keys')
        self.cache_path = os.path.join(self.tmpdir, 'cache')
        self.exclude_file_path = os.path.join(self.tmpdir, 'excludes')
        os.environ['ATTIC_KEYS_DIR'] = self.keys_path
        os.environ['ATTIC_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        with open(self.exclude_file_path, 'wb') as fd:
            fd.write(b'input/file2\n# A commment line, then a blank line\n\n')
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
        stdin, stdout, stderr = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = StringIO()
            output = StringIO()
            sys.stdout = sys.stderr = output
            ret = self.archiver.run(args)
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr
            if ret != exit_code:
                print(output.getvalue())
            self.assert_equal(exit_code, ret)
            return output.getvalue()
        finally:
            sys.stdin, sys.stdout, sys.stderr = stdin, stdout, stderr

    def create_src_archive(self, name):
        self.attic('create', self.repository_location + '::' + name, src_dir)


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
        # 2600-01-01 > 2**64 ns
        os.utime('input/empty', (19880895600, 19880895600))
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('flagfile', size=1024)
        # Directory
        self.create_regular_file('dir2/file2', size=1024 * 80)
        # File owner
        os.chown('input/file1', 100, 200)
        # File mode
        os.chmod('input/file1', 0o7755)
        os.chmod('input/dir2', 0o555)
        # Block device
        os.mknod('input/bdev', 0o600 | stat.S_IFBLK,  os.makedev(10, 20))
        # Char device
        os.mknod('input/cdev', 0o600 | stat.S_IFCHR,  os.makedev(30, 40))
        # Hard link
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'hardlink'))
        # Symlink
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        if xattr.is_enabled():
            xattr.setxattr(os.path.join(self.input_path, 'file1'), 'user.foo', b'bar')
            xattr.setxattr(os.path.join(self.input_path, 'link1'), 'user.foo_symlink', b'bar_symlink', follow_symlinks=False)
        # FIFO node
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        if has_lchflags:
            os.lchflags(os.path.join(self.input_path, 'flagfile'), stat.UF_NODUMP)

    def test_basic_functionality(self):
        self.create_test_files()
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        self.attic('create', self.repository_location + '::test.2', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test')
        self.assert_equal(len(self.attic('list', self.repository_location).splitlines()), 2)
        self.assert_equal(len(self.attic('list', self.repository_location + '::test').splitlines()), 11)
        self.assert_dirs_equal('input', 'output/input')
        info_output = self.attic('info', self.repository_location + '::test')
        self.assert_in('Number of files: 4', info_output)
        shutil.rmtree(self.cache_path)
        with environment_variable(ATTIC_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK='1'):
            info_output2 = self.attic('info', self.repository_location + '::test')
        # info_output2 starts with some "initializing cache" text but should
        # end the same way as info_output
        assert info_output2.endswith(info_output)

    def _extract_repository_id(self, path):
        return Repository(self.repository_path).id

    def _set_repository_id(self, path, id):
        config = RawConfigParser()
        config.read(os.path.join(path, 'config'))
        config.set('repository', 'id', hexlify(id).decode('ascii'))
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)
        return Repository(self.repository_path).id

    def test_repository_swap_detection(self):
        self.create_test_files()
        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
        self.attic('init', '--encryption=passphrase', self.repository_location)
        repository_id = self._extract_repository_id(self.repository_path)
        self.attic('create', self.repository_location + '::test', 'input')
        shutil.rmtree(self.repository_path)
        self.attic('init', '--encryption=none', self.repository_location)
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        self.assert_raises(Cache.EncryptionMethodMismatch, lambda :self.attic('create', self.repository_location + '::test.2', 'input'))

    def test_repository_swap_detection2(self):
        self.create_test_files()
        self.attic('init', '--encryption=none', self.repository_location + '_unencrypted')
        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
        self.attic('init', '--encryption=passphrase', self.repository_location + '_encrypted')
        self.attic('create', self.repository_location + '_encrypted::test', 'input')
        shutil.rmtree(self.repository_path + '_encrypted')
        os.rename(self.repository_path + '_unencrypted', self.repository_path + '_encrypted')
        self.assert_raises(Cache.RepositoryAccessAborted, lambda :self.attic('create', self.repository_location + '_encrypted::test.2', 'input'))

    def test_strip_components(self):
        self.attic('init', self.repository_location)
        self.create_regular_file('dir/file')
        self.attic('create', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test', '--strip-components', '3')
            self.assert_true(not os.path.exists('file'))
            with self.assert_creates_file('file'):
                self.attic('extract', self.repository_location + '::test', '--strip-components', '2')
            with self.assert_creates_file('dir/file'):
                self.attic('extract', self.repository_location + '::test', '--strip-components', '1')
            with self.assert_creates_file('input/dir/file'):
                self.attic('extract', self.repository_location + '::test', '--strip-components', '0')

    def test_extract_include_exclude(self):
        self.attic('init', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('file2', size=1024 * 80)
        self.create_regular_file('file3', size=1024 * 80)
        self.create_regular_file('file4', size=1024 * 80)
        self.attic('create', '--exclude=input/file4', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test', 'input/file1', )
        self.assert_equal(sorted(os.listdir('output/input')), ['file1'])
        with changedir('output'):
            self.attic('extract', '--exclude=input/file2', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])
        with changedir('output'):
            self.attic('extract', '--exclude-from=' + self.exclude_file_path, self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])

    def test_exclude_caches(self):
        self.attic('init', self.repository_location)
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('cache1/CACHEDIR.TAG', contents = b'Signature: 8a477f597d28d172789f06886806bc55 extra stuff')
        self.create_regular_file('cache2/CACHEDIR.TAG', contents = b'invalid signature')
        self.attic('create', '--exclude-caches', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.attic('extract', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['cache2', 'file1'])
        self.assert_equal(sorted(os.listdir('output/input/cache2')), ['CACHEDIR.TAG'])

    def test_path_normalization(self):
        self.attic('init', self.repository_location)
        self.create_regular_file('dir1/dir2/file', size=1024 * 80)
        with changedir('input/dir1/dir2'):
            self.attic('create', self.repository_location + '::test', '../../../input/dir1/../dir1/dir2/..')
        output = self.attic('list', self.repository_location + '::test')
        self.assert_not_in('..', output)
        self.assert_in(' input/dir1/dir2/file', output)

    def test_repeated_files(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input', 'input')

    def test_overwrite(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
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
        self.create_regular_file('file1', size=1024 * 80)
        self.create_regular_file('dir2/file2', size=1024 * 80)
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        self.attic('create', self.repository_location + '::test.2', 'input')
        self.attic('extract', '--dry-run', self.repository_location + '::test')
        self.attic('extract', '--dry-run', self.repository_location + '::test.2')
        self.attic('delete', self.repository_location + '::test')
        self.attic('extract', '--dry-run', self.repository_location + '::test.2')
        self.attic('delete', self.repository_location + '::test.2')
        # Make sure all data except the manifest has been deleted
        repository = Repository(self.repository_path)
        self.assert_equal(len(repository), 1)

    def test_corrupted_repository(self):
        self.attic('init', self.repository_location)
        self.create_src_archive('test')
        self.attic('extract', '--dry-run', self.repository_location + '::test')
        self.attic('check', self.repository_location)
        name = sorted(os.listdir(os.path.join(self.tmpdir, 'repository', 'data', '0')), reverse=True)[0]
        fd = open(os.path.join(self.tmpdir, 'repository', 'data', '0', name), 'r+')
        fd.seek(100)
        fd.write('XXXX')
        fd.close()
        self.attic('check', self.repository_location, exit_code=1)

    def test_readonly_repository(self):
        self.attic('init', self.repository_location)
        self.create_src_archive('test')
        os.system('chmod -R ugo-w ' + self.repository_path)
        try:
            self.attic('extract', '--dry-run', self.repository_location + '::test')
        finally:
            # Restore permissions so shutil.rmtree is able to delete it
            os.system('chmod -R u+w ' + self.repository_path)

    def test_cmdline_compatibility(self):
        self.create_regular_file('file1', size=1024 * 80)
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test', 'input')
        output = self.attic('verify', '-v', self.repository_location + '::test')
        self.assert_in('"attic verify" has been deprecated', output)
        output = self.attic('prune', self.repository_location, '--hourly=1')
        self.assert_in('"--hourly" has been deprecated. Use "--keep-hourly" instead', output)

    def test_prune_repository(self):
        self.attic('init', self.repository_location)
        self.attic('create', self.repository_location + '::test1', src_dir)
        self.attic('create', self.repository_location + '::test2', src_dir)
        output = self.attic('prune', '-v', '--dry-run', self.repository_location, '--keep-daily=2')
        self.assert_in('Keeping archive: test2', output)
        self.assert_in('Would prune:     test1', output)
        output = self.attic('list', self.repository_location)
        self.assert_in('test1', output)
        self.assert_in('test2', output)
        self.attic('prune', self.repository_location, '--keep-daily=2')
        output = self.attic('list', self.repository_location)
        self.assert_not_in('test1', output)
        self.assert_in('test2', output)

    def test_usage(self):
        self.assert_raises(SystemExit, lambda: self.attic())
        self.assert_raises(SystemExit, lambda: self.attic('-h'))

    @unittest.skipUnless(has_llfuse, 'llfuse not installed')
    def test_fuse_mount_repository(self):
        mountpoint = os.path.join(self.tmpdir, 'mountpoint')
        os.mkdir(mountpoint)
        self.attic('init', self.repository_location)
        self.create_test_files()
        self.attic('create', self.repository_location + '::archive', 'input')
        self.attic('create', self.repository_location + '::archive2', 'input')
        try:
            self.attic('mount', self.repository_location, mountpoint, fork=True)
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
            for key, _ in repository.open_index(repository.get_transaction_id()).iteritems():
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


class ArchiverCheckTestCase(ArchiverTestCaseBase):

    def setUp(self):
        super(ArchiverCheckTestCase, self).setUp()
        with patch.object(ChunkBuffer, 'BUFFER_SIZE', 10):
            self.attic('init', self.repository_location)
            self.create_src_archive('archive1')
            self.create_src_archive('archive2')

    def open_archive(self, name):
        repository = Repository(self.repository_path)
        manifest, key = Manifest.load(repository)
        archive = Archive(repository, key, manifest, name)
        return archive, repository

    def test_check_usage(self):
        output = self.attic('check', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)
        output = self.attic('check', '--repository-only', self.repository_location, exit_code=0)
        self.assert_in('Starting repository check', output)
        self.assert_not_in('Starting archive consistency check', output)
        output = self.attic('check', '--archives-only', self.repository_location, exit_code=0)
        self.assert_not_in('Starting repository check', output)
        self.assert_in('Starting archive consistency check', output)

    def test_missing_file_chunk(self):
        archive, repository = self.open_archive('archive1')
        for item in archive.iter_items():
            if item[b'path'].endswith('testsuite/archiver.py'):
                repository.delete(item[b'chunks'][-1][0])
                break
        repository.commit()
        self.attic('check', self.repository_location, exit_code=1)
        self.attic('check', '--repair', self.repository_location, exit_code=0)
        self.attic('check', self.repository_location, exit_code=0)

    def test_missing_archive_item_chunk(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(archive.metadata[b'items'][-5])
        repository.commit()
        self.attic('check', self.repository_location, exit_code=1)
        self.attic('check', '--repair', self.repository_location, exit_code=0)
        self.attic('check', self.repository_location, exit_code=0)

    def test_missing_archive_metadata(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(archive.id)
        repository.commit()
        self.attic('check', self.repository_location, exit_code=1)
        self.attic('check', '--repair', self.repository_location, exit_code=0)
        self.attic('check', self.repository_location, exit_code=0)

    def test_missing_manifest(self):
        archive, repository = self.open_archive('archive1')
        repository.delete(Manifest.MANIFEST_ID)
        repository.commit()
        self.attic('check', self.repository_location, exit_code=1)
        output = self.attic('check', '--repair', self.repository_location, exit_code=0)
        self.assert_in('archive1', output)
        self.assert_in('archive2', output)
        self.attic('check', self.repository_location, exit_code=0)

    def test_extra_chunks(self):
        self.attic('check', self.repository_location, exit_code=0)
        repository = Repository(self.repository_location)
        repository.put(b'01234567890123456789012345678901', b'xxxx')
        repository.commit()
        repository.close()
        self.attic('check', self.repository_location, exit_code=1)
        self.attic('check', self.repository_location, exit_code=1)
        self.attic('check', '--repair', self.repository_location, exit_code=0)
        self.attic('check', self.repository_location, exit_code=0)
        self.attic('extract', '--dry-run', self.repository_location + '::archive1', exit_code=0)


class RemoteArchiverTestCase(ArchiverTestCase):
    prefix = '__testsuite__:'

    def test_remote_repo_restrict_to_path(self):
        self.attic('init', self.repository_location)
        path_prefix = os.path.dirname(self.repository_path)
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo']):
            self.assert_raises(PathNotAllowed, lambda: self.attic('init', self.repository_location + '_1'))
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', path_prefix]):
            self.attic('init', self.repository_location + '_2')
        with patch.object(RemoteRepository, 'extra_test_args', ['--restrict-to-path', '/foo', '--restrict-to-path', path_prefix]):
            self.attic('init', self.repository_location + '_3')
