from ..lrucache import LRUCache
from . import BaseTestCase


class LRUCacheTestCase(BaseTestCase):

    def test(self):
        c = LRUCache(2)
        self.assert_equal(len(c), 0)
        for i, x in enumerate('abc'):
            c[x] = i
        self.assert_equal(len(c), 2)
        self.assert_equal(set(c), set(['b', 'c']))
        self.assert_equal(set(c.items()), set([('b', 1), ('c', 2)]))
        self.assert_equal(False, 'a' in c)
        self.assert_equal(True, 'b' in c)
        self.assert_raises(KeyError, lambda: c['a'])
        self.assert_equal(c['b'], 1)
        self.assert_equal(c['c'], 2)
        c['d'] = 3
        self.assert_equal(len(c), 2)
        self.assert_equal(c['c'], 2)
        self.assert_equal(c['d'], 3)
        c['c'] = 22
        c['e'] = 4
        self.assert_equal(len(c), 2)
        self.assert_raises(KeyError, lambda: c['d'])
        self.assert_equal(c['c'], 22)
        self.assert_equal(c['e'], 4)
        del c['c']
        self.assert_equal(len(c), 1)
        self.assert_raises(KeyError, lambda: c['c'])
        self.assert_equal(c['e'], 4)

    def test_pop(self):
        c = LRUCache(2)
        c[1] = 1
        c[2] = 2
        c.pop(1)
        c[3] = 3
