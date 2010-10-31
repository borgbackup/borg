import filecmp
import os
from StringIO import StringIO
import sys
import shutil
import tempfile
import unittest
from xattr import xattr, XATTR_NOFOLLOW

from . import store
from .archiver import Archiver


class Test(unittest.TestCase):

    def setUp(self):
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp()
        self.store_path = os.path.join(self.tmpdir, 'store')
        self.input_path = os.path.join(self.tmpdir, 'input')
        self.output_path = os.path.join(self.tmpdir, 'output')
        os.mkdir(self.input_path)
        os.mkdir(self.output_path)
        os.chdir(self.tmpdir)
        self.keychain = '/tmp/_test_dedupstore.keychain'
        if not os.path.exists(self.keychain):
            self.darc('init-keychain')
        self.darc('init', self.store_path)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def darc(self, *args, **kwargs):
        exit_code = kwargs.get('exit_code', 0)
        args = ['--keychain', self.keychain] + list(args)
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
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__))
        self.darc('create', self.store_path + '::' + name, src_dir)

    def create_regual_file(self, name, size=0):
        filename = os.path.join(self.input_path, name)
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as fd:
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
        self.create_regual_file('file1', size=1024*80)
        self.create_regual_file('dir2/file2', size=1024*80)
        x = xattr(os.path.join(self.input_path, 'file1'))
        x.set('user:foo', 'bar')
        os.symlink('somewhere', os.path.join(self.input_path, 'link1'))
        os.mkfifo(os.path.join(self.input_path, 'fifo1'))
        self.darc('create', self.store_path + '::test', 'input')
        self.darc('extract', self.store_path + '::test', 'output')
        self.diff_dirs('input', 'output/input')

    def test_corrupted_store(self):
        self.create_src_archive('test')
        self.darc('verify', self.store_path + '::test')
        fd = open(os.path.join(self.tmpdir, 'store', 'bands', '0', '0'), 'r+')
        fd.seek(100)
        fd.write('X')
        fd.close()
        self.darc('verify', self.store_path + '::test', exit_code=1)

    def test_keychain(self):
        keychain = os.path.join(self.tmpdir, 'keychain')
        self.darc('-k', keychain, 'init-keychain')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test))
    suite.addTest(store.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
