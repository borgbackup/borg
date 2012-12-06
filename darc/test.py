from __future__ import with_statement
import doctest
import filecmp
import os
from StringIO import StringIO
import sys
import shutil
import tempfile
import unittest
from xattr import xattr, XATTR_NOFOLLOW

from . import helpers, lrucache
from .archiver import Archiver
from .key import suite as KeySuite
from .store import Store, suite as StoreSuite
from .remote import Store, suite as RemoteStoreSuite


class Test(unittest.TestCase):

    prefix = ''

    def setUp(self):
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp()
        self.store_path = os.path.join(self.tmpdir, 'store')
        self.store_location = self.prefix + self.store_path
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
                print output.getvalue()
            self.assertEqual(exit_code, ret)
            return output.getvalue()
        finally:
            sys.stdout, sys.stderr = stdout, stderr

    def create_src_archive(self, name):
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__), '..')
        self.darc('init', self.store_location)
        self.darc('create', self.store_location + '::' + name, src_dir)

    def create_regual_file(self, name, size=0):
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wbx') as fd:
            fd.write('X' * size)

    def get_xattrs(self, path):
        try:
            return dict(xattr(path, XATTR_NOFOLLOW))
        except IOError:
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
            attrs = ['st_mode', 'st_uid', 'st_gid']
            # We can't restore symlink atime/mtime right now
            if not os.path.islink(path1):
                attrs.append('st_mtime')
            d1 = [filename] + [getattr(s1, a) for a in attrs]
            d2 = [filename] + [getattr(s2, a) for a in attrs]
            d1.append(self.get_xattrs(path1))
            d2.append(self.get_xattrs(path2))
            self.assertEqual(d1, d2)

    def test_basic_functionality(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        os.chmod('input/file1', 0600)
        os.chmod('input/dir2', 0700)
        x = xattr(os.path.join(self.input_path, 'file1'))
        x.set('user.foo', 'bar')
        os.link(os.path.join(self.input_path, 'file1'),
                os.path.join(self.input_path, 'hardlink'))
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        self.darc('init', self.store_location)
        self.darc('create', self.store_location + '::test', 'input')
        self.darc('create', self.store_location + '::test.2', 'input')
        self.darc('extract', self.store_location + '::test', 'output')
        self.diff_dirs('input', 'output/input')
        info_output = self.darc('info', self.store_location + '::test')
        shutil.rmtree(self.cache_path)
        info_output2 = self.darc('info', self.store_location + '::test')
        # info_output2 starts with some "initializing cache" text but should
        # end the same way as info_output
        assert info_output2.endswith(info_output)

    def test_overwrite(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.darc('init', self.store_location)
        self.darc('create', self.store_location + '::test', 'input')
        # Overwriting regular files and directories should be supported
        os.mkdir('output/input')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/dir2')
        self.darc('extract', self.store_location + '::test', 'output')
        self.diff_dirs('input', 'output/input')
        # But non-empty dirs should fail
        os.unlink('output/input/file1')
        os.mkdir('output/input/file1')
        os.mkdir('output/input/file1/dir')
        self.darc('extract', self.store_location + '::test', 'output', exit_code=1)

    def test_delete(self):
        self.create_regual_file('file1', size=1024 * 80)
        self.create_regual_file('dir2/file2', size=1024 * 80)
        self.darc('init', self.store_location)
        self.darc('create', self.store_location + '::test', 'input')
        self.darc('create', self.store_location + '::test.2', 'input')
        self.darc('verify', self.store_location + '::test')
        self.darc('verify', self.store_location + '::test.2')
        self.darc('delete', self.store_location + '::test')
        self.darc('verify', self.store_location + '::test.2')
        self.darc('delete', self.store_location + '::test.2')
        # Make sure all data except the manifest has been deleted
        store = Store(self.store_path)
        self.assertEqual(store._len(), 1)

    def test_corrupted_store(self):
        self.create_src_archive('test')
        self.darc('verify', self.store_location + '::test')
        name = sorted(os.listdir(os.path.join(self.tmpdir, 'store', 'data', '0')), reverse=True)[0]
        fd = open(os.path.join(self.tmpdir, 'store', 'data', '0', name), 'r+')
        fd.seek(100)
        fd.write('X')
        fd.close()
        self.darc('verify', self.store_location + '::test', exit_code=1)

    def test_prune_store(self):
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__))
        self.darc('init', self.store_location)
        self.darc('create', self.store_location + '::test1', src_dir)
        self.darc('create', self.store_location + '::test2', src_dir)
        self.darc('prune', self.store_location, '--daily=2')
        output = self.darc('list', self.store_location)
        assert 'test1' not in output
        assert 'test2' in output


class RemoteTest(Test):
    prefix = 'localhost:'


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RemoteTest))
    suite.addTest(KeySuite())
    suite.addTest(StoreSuite())
    suite.addTest(RemoteStoreSuite())
    suite.addTest(doctest.DocTestSuite(helpers))
    suite.addTest(lrucache.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
