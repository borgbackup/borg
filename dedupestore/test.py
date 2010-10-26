import os
import shutil
import tempfile
import unittest

from .archiver import Archiver
from . import store


class Test(unittest.TestCase):

    def setUp(self):
        self.archiver = Archiver()
        self.tmpdir = tempfile.mkdtemp()
        self.store_path = os.path.join(self.tmpdir, 'store')
        self.keychain = '/tmp/_test_dedupstore.keychain'
        if not os.path.exists(self.keychain):
            self.dedupestore('keychain', 'generate')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def dedupestore(self, *args, **kwargs):
        exit_code = kwargs.get('exit_code', 0)
        args = ['--keychain', self.keychain] + list(args)
        self.assertEqual(exit_code, self.archiver.run(args))

    def create_src_archive(self, name):
        src_dir = os.path.join(os.getcwd(), os.path.dirname(__file__))
        self.dedupestore('create', self.store_path + '::' + name, src_dir)

    def test_basic_functionality(self):
        self.create_src_archive('test')
        self.dedupestore('list', self.store_path)
        self.dedupestore('list', self.store_path + '::test')
        self.dedupestore('info', self.store_path + '::test')
        self.dedupestore('verify', self.store_path + '::test')
        dest_dir = os.path.join(self.tmpdir, 'dest')
        self.dedupestore('extract', self.store_path + '::test', dest_dir)
        self.dedupestore('delete', self.store_path + '::test')

    def test_corrupted_store(self):
        self.create_src_archive('test')
        self.dedupestore('verify', self.store_path + '::test')
        fd = open(os.path.join(self.tmpdir, 'store', 'bands', '0', '0'), 'r+')
        fd.seek(1000)
        fd.write('X')
        fd.close()
        self.dedupestore('verify', self.store_path + '::test', exit_code=1)

    def test_symlinks(self):
        testdir = os.path.join(self.tmpdir, 'linktest')
        os.mkdir(testdir)
        os.symlink('/tmp/somewhere', os.path.join(testdir, 'link'))
        self.dedupestore('create', self.store_path + '::symlinktest', testdir)
        dest_dir = os.path.join(self.tmpdir, 'dest')
        self.dedupestore('extract', self.store_path + '::symlinktest', dest_dir)
        dest = os.path.join(dest_dir, testdir[1:])
        self.assertEqual(os.path.islink(os.path.join(dest, 'link')), True)
        self.assertEqual(os.readlink(os.path.join(dest, 'link')), '/tmp/somewhere')


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test))
    suite.addTest(store.suite())
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
