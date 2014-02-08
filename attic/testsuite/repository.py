import os
import shutil
import tempfile
from attic.hashindex import NSIndex
from attic.helpers import Location
from attic.remote import RemoteRepository
from attic.repository import Repository
from attic.testsuite import AtticTestCase


class RepositoryTestCase(AtticTestCase):

    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, 'repository'), create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)

    def tearDown(self):
        self.repository.close()
        shutil.rmtree(self.tmppath)

    def test1(self):
        for x in range(100):
            self.repository.put(('%-32d' % x).encode('ascii'), b'SOMEDATA')
        key50 = ('%-32d' % 50).encode('ascii')
        self.assert_equal(self.repository.get(key50), b'SOMEDATA')
        self.repository.delete(key50)
        self.assert_raises(Repository.DoesNotExist, lambda: self.repository.get(key50))
        self.repository.commit()
        self.repository.close()
        repository2 = self.open()
        self.assert_raises(Repository.DoesNotExist, lambda: repository2.get(key50))
        for x in range(100):
            if x == 50:
                continue
            self.assert_equal(repository2.get(('%-32d' % x).encode('ascii')), b'SOMEDATA')
        repository2.close()

    def test2(self):
        """Test multiple sequential transactions
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.put(b'00000000000000000000000000000001', b'foo')
        self.repository.commit()
        self.repository.delete(b'00000000000000000000000000000000')
        self.repository.put(b'00000000000000000000000000000001', b'bar')
        self.repository.commit()
        self.assert_equal(self.repository.get(b'00000000000000000000000000000001'), b'bar')

    def test_consistency(self):
        """Test cache consistency
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')
        self.repository.put(b'00000000000000000000000000000000', b'foo2')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo2')
        self.repository.put(b'00000000000000000000000000000000', b'bar')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'bar')
        self.repository.delete(b'00000000000000000000000000000000')
        self.assert_raises(Repository.DoesNotExist, lambda: self.repository.get(b'00000000000000000000000000000000'))

    def test_consistency2(self):
        """Test cache consistency2
        """
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')
        self.repository.commit()
        self.repository.put(b'00000000000000000000000000000000', b'foo2')
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo2')
        self.repository.rollback()
        self.assert_equal(self.repository.get(b'00000000000000000000000000000000'), b'foo')

    def test_single_kind_transactions(self):
        # put
        self.repository.put(b'00000000000000000000000000000000', b'foo')
        self.repository.commit()
        self.repository.close()
        # replace
        self.repository = self.open()
        self.repository.put(b'00000000000000000000000000000000', b'bar')
        self.repository.commit()
        self.repository.close()
        # delete
        self.repository = self.open()
        self.repository.delete(b'00000000000000000000000000000000')
        self.repository.commit()


class RepositoryCheckTestCase(AtticTestCase):

    def open(self, create=False):
        return Repository(os.path.join(self.tmppath, 'repository'), create=create)

    def reopen(self):
        if self.repository:
            self.repository.close()
        self.repository = self.open()

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.repository = self.open(create=True)

    def tearDown(self):
        self.repository.close()
        shutil.rmtree(self.tmppath)

    def add_objects(self, ids):
        for id_ in ids:
            self.repository.put(('%032d' % id_).encode('ascii'), b'data')
        self.repository.commit()

    def get_head(self):
        return sorted(int(n) for n in os.listdir(os.path.join(self.tmppath, 'repository', 'data', '0')) if n.isdigit())[-1]

    def open_index(self):
        return NSIndex(os.path.join(self.tmppath, 'repository', 'index.{}'.format(self.get_head())))

    def corrupt_object(self, id_):
        idx = self.open_index()
        segment, offset = idx[('%032d' % id_).encode('ascii')]
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', str(segment)), 'r+b') as fd:
            fd.seek(offset)
            fd.write(b'BOOM')

    def list_objects(self):
        return set((int(key) for key, _ in list(self.open_index().iteritems())))

    def test_check(self):
        self.add_objects([1, 2, 3])
        self.add_objects([4, 5, 6])
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())
        self.assert_equal(True, self.repository.check())
        self.corrupt_object(5)
        self.reopen()
        self.assert_equal(False, self.repository.check())
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())

    def test_check_repair(self):
        self.add_objects([1, 2, 3])
        self.add_objects([4, 5, 6])
        self.assert_equal(set([1, 2, 3, 4, 5, 6]), self.list_objects())
        self.assert_equal(True, self.repository.check())
        self.corrupt_object(5)
        self.reopen()
        self.assert_equal(False, self.repository.check(repair=True))
        self.assert_equal(set([1, 2, 3, 4, 6]), self.list_objects())


    def test_check_missing_or_corrupt_commit_tag(self):
        self.add_objects([1, 2, 3])
        self.assert_equal(set([1, 2, 3]), self.list_objects())
        with open(os.path.join(self.tmppath, 'repository', 'data', '0', str(self.get_head())), 'ab') as fd:
            fd.write(b'X')
        self.assert_raises(Repository.CheckNeeded, lambda: self.repository.get(bytes(32)))

class RemoteRepositoryTestCase(RepositoryTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)


class RemoteRepositoryCheckTestCase(RepositoryCheckTestCase):

    def open(self, create=False):
        return RemoteRepository(Location('__testsuite__:' + os.path.join(self.tmppath, 'repository')), create=create)
