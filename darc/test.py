import doctest
import filecmp
import os
from io import BytesIO, StringIO
import stat
import sys
import shutil
import tempfile
import unittest
import xattr

from . import helpers, lrucache, crypto
from .chunker import chunkify, buzhash, buzhash_update
from .archiver import Archiver
from .key import suite as KeySuite
from .repository import Repository, suite as RepositorySuite
from .remote import Repository, suite as RemoteRepositorySuite

has_mtime_ns = sys.version >= '3.3'
utime_supports_fd = os.utime in getattr(os, 'supports_fd', {})


class Test(unittest.TestCase):

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
        os.environ['DARC_KEYS_DIR'] = self.keys_path
        os.environ['DARC_CACHE_DIR'] = self.cache_path
        os.mkdir(self.input_path)
        os.mkdir(self.output_path)
        os.mkdir(self.keys_path)
        os.mkdir(self.cache_path)
        os.chdir(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

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
            self.assertEqual(exit_code, ret)
            return output.getvalue()
        finally:
            sys.stdout, sys.stderr = stdout, stderr

    def create_src_archive(self, name):
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__), '..')
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
            return xattr.get_all(path, True)
        except EnvironmentError:
            return {}

    def diff_dirs(self, dir1, dir2):
        diff = filecmp.dircmp(dir1, dir2)
        self.assertEqual(diff.left_only, [])
        self.assertEqual(diff.right_only, [])
        self.assertEqual(diff.diff_files, [])
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
            self.assertEqual(d1, d2)

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
        xattr.set(os.path.join(self.input_path, 'file1'), 'user.foo', 'bar')
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
        self.darc('extract', self.repository_location + '::test', 'output')
        self.assertEqual(len(self.darc('list', self.repository_location).splitlines()), 2)
        self.assertEqual(len(self.darc('list', self.repository_location + '::test').splitlines()), 9)
        self.diff_dirs('input', 'output/input')
        info_output = self.darc('info', self.repository_location + '::test')
        shutil.rmtree(self.cache_path)
        info_output2 = self.darc('info', self.repository_location + '::test')
        # info_output2 starts with some "initializing cache" text but should
        # end the same way as info_output
        assert info_output2.endswith(info_output)

    def test_overwrite(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test', 'input')
        # Overwriting regular files and directories should be supported
        os.mkdir('output/input')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/dir2')
        self.darc('extract', self.repository_location + '::test', 'output')
        self.diff_dirs('input', 'output/input')
        # But non-empty dirs should fail
        os.unlink('output/input/file1')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/file1/dir')
        self.darc('extract', self.repository_location + '::test', 'output', exit_code=1)

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
        self.assertEqual(repository._len(), 1)

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
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__))
        self.darc('init', self.repository_location)
        self.darc('create', self.repository_location + '::test1', src_dir)
        self.darc('create', self.repository_location + '::test2', src_dir)
        self.darc('prune', self.repository_location, '--daily=2')
        output = self.darc('list', self.repository_location)
        assert 'test1' not in output
        assert 'test2' in output


class ChunkTest(unittest.TestCase):

    def test_chunkify(self):
        data = b'0' * 1024 * 1024 * 15 + b'Y'
        parts = [bytes(c) for c in chunkify(BytesIO(data), 2, 0x3, 2, 0)]
        self.assertEqual(len(parts), 2)
        self.assertEqual(b''.join(parts), data)
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b''), 2, 0x3, 2, 0)], [])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 2, 0x3, 2, 0)], [b'fooba', b'rboobaz', b'fooba', b'rboobaz', b'fooba', b'rboobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 2, 0x3, 2, 1)], [b'fo', b'obarb', b'oob', b'azf', b'oobarb', b'oob', b'azf', b'oobarb', b'oobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 2, 0x3, 2, 2)], [b'foob', b'ar', b'boobazfoob', b'ar', b'boobazfoob', b'ar', b'boobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 3, 0)], [b'foobarboobaz' * 3])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 3, 1)], [b'foobar', b'boo', b'bazfo', b'obar', b'boo', b'bazfo', b'obar', b'boobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 3, 2)], [b'foo', b'barboobaz', b'foo', b'barboobaz', b'foo', b'barboobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 4, 0)], [b'foobarboobaz' * 3])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 4, 1)], [b'foobar', b'boobazfo', b'obar', b'boobazfo', b'obar', b'boobaz'])
        self.assertEqual([bytes(c) for c in chunkify(BytesIO(b'foobarboobaz' * 3), 3, 0x3, 4, 2)], [b'foob', b'arboobaz', b'foob', b'arboobaz', b'foob', b'arboobaz'])

    def test_buzhash(self):
        self.assertEqual(buzhash(b'abcdefghijklmnop', 0), 3795437769)
        self.assertEqual(buzhash(b'abcdefghijklmnop', 1), 3795400502)
        self.assertEqual(buzhash(b'abcdefghijklmnop', 1), buzhash_update(buzhash(b'Xabcdefghijklmno', 1), ord('X'), ord('p'), 16, 1))


class RemoteTest(Test):
    prefix = 'localhost:'


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ChunkTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RemoteTest))
    suite.addTest(KeySuite())
    suite.addTest(RepositorySuite())
    suite.addTest(RemoteRepositorySuite())
    suite.addTest(doctest.DocTestSuite(helpers))
    suite.addTest(lrucache.suite())
    suite.addTest(crypto.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
