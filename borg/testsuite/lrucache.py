from ..lrucache import LRUCache
from . import BaseTestCase
from tempfile import TemporaryFile


class LRUCacheTestCase(BaseTestCase):

    def test(self):
        c = LRUCache(2, dispose=lambda _: None)
        self.assert_equal(len(c), 0)
        for i, x in enumerate('abc'):
            c[x] = i
        self.assert_equal(len(c), 2)
        self.assert_equal(c.items(), set([('b', 1), ('c', 2)]))
        self.assert_equal(False, 'a' in c)
        self.assert_equal(True, 'b' in c)
        self.assert_raises(KeyError, lambda: c['a'])
        self.assert_equal(c['b'], 1)
        self.assert_equal(c['c'], 2)
        c['d'] = 3
        self.assert_equal(len(c), 2)
        self.assert_equal(c['c'], 2)
        self.assert_equal(c['d'], 3)
        del c['c']
        self.assert_equal(len(c), 1)
        self.assert_raises(KeyError, lambda: c['c'])
        self.assert_equal(c['d'], 3)
        c.clear()
        self.assert_equal(c.items(), set())

    def test_dispose(self):
        c = LRUCache(2, dispose=lambda f: f.close())
        f1 = TemporaryFile()
        f2 = TemporaryFile()
        f3 = TemporaryFile()
        c[1] = f1
        c[2] = f2
        self.assert_equal(False, f2.closed)
        c[3] = f3
        self.assert_equal(False, 1 in c)
        self.assert_equal(True, f1.closed)
        self.assert_equal(True, 2 in c)
        self.assert_equal(False, f2.closed)
        del c[2]
        self.assert_equal(False, 2 in c)
        self.assert_equal(True, f2.closed)
        c.clear()
        self.assert_equal(c.items(), set())
        self.assert_equal(True, f3.closed)
