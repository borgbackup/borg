import filecmp
import os
from io import StringIO
import stat
import sys
import shutil
import tempfile
from darc import xattr
from darc.archiver import Archiver
from darc.repository import Repository
from darc.testsuite import DarcTestCase

has_mtime_ns = sys.version >= '3.3'
utime_supports_fd = os.utime in getattr(os, 'supports_fd', {})

src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__), '..', '..')

class changedir:
    def __init__(self, dir):
        self.dir = dir

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.dir)

    def __exit__(self, *args, **kw):
        os.chdir(self.old)


class ArchiverTestCase(DarcTestCase):

    prefix = ''

    def setUp(self):
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp(dir=os.getcwd())
        self.repository_path = os.path.join(self.tmpdir, 'repository')
        self.repository_location = self.prefix + self.repository_path
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        self.keys_path = os.path.join(self.tmpdir, 'keys')
        self.cache_path = os.path.join(self.tmpdir, 'cache')
        os.environ['DARC_KEYS_DIR'] = self.keys_path
        os.environ['DARC_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        self._old_wd = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        os.chdir(self._old_wd)

    def darc(self, *args, **kwargs):
        exit_code = kwargs.get('exit_code', 0)
        args = list(args)
        try:
            stdout, stderr = sys.stdout, sys.stderr
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
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::' + name, src_dir)

    def create_regual_file(self, name, size=0):
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
            fd.write(b'X' * size)

    def get_xattrs(self, path):
        try:
            return xattr.get_all(path)
        except EnvironmentError:
            return {}

    def diff_dirs(self, dir1, dir2):
        diff = filecmp.dircmp(dir1, dir2)
        self.assert_equal(diff.left_only, [])
        self.assert_equal(diff.right_only, [])
        self.assert_equal(diff.diff_files, [])
        for filename in diff.common:
            path1 = os.path.join(dir1, filename)
            path2 = os.path.join(dir2, filename)
            s1 = os.lstat(path1)
            s2 = os.lstat(path2)
            attrs = ['st_mode', 'st_uid', 'st_gid', 'st_rdev']
            if not os.path.islink(path1) or utime_supports_fd:
                attrs.append('st_mtime_ns' if has_mtime_ns else 'st_mtime')
            d1 = [filename] + [getattr(s1, a) for a in attrs]
            d2 = [filename] + [getattr(s2, a) for a in attrs]
            # 'st_mtime precision is limited'
            if attrs[-1] == 'st_mtime':
                d1[-1] = round(d1[-1], 4)
                d2[-1] = round(d2[-1], 4)
            d1.append(self.get_xattrs(path1))
            d2.append(self.get_xattrs(path2))
            self.assert_equal(d1, d2)

    def test_basic_functionality(self):
        # File
        self.create_regual_file('file1', size=1024 * 80)
        # Directory
        self.create_regual_file('dir2/file2', size=1024 * 80)
        # File owner
        os.chown('input/file1', 100, 200)
        # File mode
        os.chmod('input/file1', 0o7755)
        os.chmod('input/dir2', 0o700)
        # Block device
        os.mknod('input/bdev', 0o600 | stat.S_IFBLK,  os.makedev(10, 20))
        # Char device
        os.mknod('input/cdev', 0o600 | stat.S_IFCHR,  os.makedev(30, 40))
        xattr.set(os.path.join(self.input_path, 'file1'), b'foo', b'bar')
        # Hard link
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'hardlink'))
        # Symlink
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        # FIFO node
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test', 'input')
        self.darc('create', self.repository_location + '::test.2', 'input')
        with changedir('output'):
            self.darc('extract', self.repository_location + '::test')
        self.assert_equal(len(self.darc('list', self.repository_location).splitlines()), 2)
        self.assert_equal(len(self.darc('list', self.repository_location + '::test').splitlines()), 9)
        self.diff_dirs('input', 'output/input')
        info_output = self.darc('info', self.repository_location + '::test')
        shutil.rmtree(self.cache_path)
        info_output2 = self.darc('info', self.repository_location + '::test')
        # info_output2 starts with some "initializing cache" text but should
        # end the same way as info_output
        assert info_output2.endswith(info_output)

    def test_extract_include_exclude(self):
        self.darc('init', self.repository_location)
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('file2', size=1024 * 80)
        self.create_regual_file('file3', size=1024 * 80)
        self.create_regual_file('file4', size=1024 * 80)
        self.darc('create', '--exclude=input/file4', self.repository_location + '::test', 'input')
        with changedir('output'):
            self.darc('extract', self.repository_location + '::test', 'input/file1', )
        self.assert_equal(sorted(os.listdir('output/input')), ['file1'])
        with changedir('output'):
            self.darc('extract', '--exclude=input/file2', self.repository_location + '::test')
        self.assert_equal(sorted(os.listdir('output/input')), ['file1', 'file3'])

    def test_overwrite(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test', 'input')
        # Overwriting regular files and directories should be supported
        os.mkdir('output/input')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/dir2')
        with changedir('output'):
            self.darc('extract', self.repository_location + '::test')
        self.diff_dirs('input', 'output/input')
        # But non-empty dirs should fail
        os.unlink('output/input/file1')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/file1/dir')
        with changedir('output'):
            self.darc('extract', self.repository_location + '::test', exit_code=1)

    def test_delete(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test', 'input')
        self.darc('create', self.repository_location + '::test.2', 'input')
        self.darc('verify', self.repository_location + '::test')
        self.darc('verify', self.repository_location + '::test.2')
        self.darc('delete', self.repository_location + '::test')
        self.darc('verify', self.repository_location + '::test.2')
        self.darc('delete', self.repository_location + '::test.2')
        # Make sure all data except the manifest has been deleted
        repository = Repository(self.repository_path)
        self.assert_equal(repository._len(), 1)

    def test_corrupted_repository(self):
        self.create_src_archive('test')
        self.darc('verify', self.repository_location + '::test')
        name = sorted(os.listdir(os.path.join(self.tmpdir, 'repository', 'data', '0')), reverse=True)[0]
        fd = open(os.path.join(self.tmpdir, 'repository', 'data', '0', name), 'r+')
        fd.seek(100)
        fd.write('X')
        fd.close()
        self.darc('verify', self.repository_location + '::test', exit_code=1)

    def test_prune_repository(self):
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test1', src_dir)
        self.darc('create', self.repository_location + '::test2', src_dir)
        self.darc('prune', self.repository_location, '--daily=2')
        output = self.darc('list', self.repository_location)
        assert 'test1' not in output
        assert 'test2' in output

    def test_usage(self):
        self.assert_raises(SystemExit, lambda: self.darc())
        self.assert_raises(SystemExit, lambda: self.darc('-h'))


class RemoteArchiverTestCase(ArchiverTestCase):
    prefix = '__testsuite__:'
