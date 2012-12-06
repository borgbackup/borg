from UserDict import DictMixin
from heapq import heappush, heapify, heapreplace, heappop
import unittest


class LRUCache(dict):

    def __init__(self, capacity):
        super(LRUCache, self).__init__()
        self._lru = []
        self._capacity = capacity

    def __setitem__(self, key, value):
        try:
            self._lru.remove(key)
        except ValueError:
            pass
        self._lru.append(key)
        while len(self._lru) > self._capacity:
            del self[self._lru[0]]
        return super(LRUCache, self).__setitem__(key, value)

    def __getitem__(self, key):
        try:
            self._lru.remove(key)
            self._lru.append(key)
        except ValueError:
            pass
        return super(LRUCache, self).__getitem__(key)

    def __delitem__(self, key):
        try:
            self._lru.remove(key)
        except ValueError:
            pass
        return super(LRUCache, self).__delitem__(key)


class LRUCacheTestCase(unittest.TestCase):

    def test(self):
        c = LRUCache(2)
        self.assertEqual(len(c), 0)
        for i, x in enumerate('abc'):
            c[x] = i
        self.assertEqual(len(c), 2)
        self.assertEqual(set(c), set(['b', 'c']))
        self.assertEqual(set(c.iteritems()), set([('b', 1), ('c', 2)]))
        self.assertEqual(False, 'a' in c)
        self.assertEqual(True, 'b' in c)
        self.assertRaises(KeyError, lambda: c['a'])
        self.assertEqual(c['b'], 1)
        self.assertEqual(c['c'], 2)
        c['d'] = 3
        self.assertEqual(len(c), 2)
        self.assertEqual(c['c'], 2)
        self.assertEqual(c['d'], 3)
        c['c'] = 22
        c['e'] = 4
        self.assertEqual(len(c), 2)
        self.assertRaises(KeyError, lambda: c['d'])
        self.assertEqual(c['c'], 22)
        self.assertEqual(c['e'], 4)
        del c['c']
        self.assertEqual(len(c), 1)
        self.assertRaises(KeyError, lambda: c['c'])
        self.assertEqual(c['e'], 4)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(LRUCacheTestCase)


if __name__ == '__main__':
    unittest.main()

