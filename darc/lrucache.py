from UserDict import DictMixin
from heapq import heappush, heapify, heapreplace, heappop
import unittest


class LRUCache(DictMixin):
    """Heap queue based Least Recently Used Cache implementation
    """

    class Node(object):
        """Internal cache node
        """
        __slots__ = ('key', 'value', 't')

        def __init__(self, key, value, t):
            self.key = key
            self.value = value
            self.t = t

        def __cmp__(self, other):
            return cmp(self.t, other.t)


    def __init__(self, size):
        self._heap = []
        self._dict = {}
        self.size = size
        self._t = 0

    def __setitem__(self, key, value):
        self._t += 1
        try:
            node = self._dict[key]
            node.value = value
            node.t = self._t
            heapify(self._heap)
        except KeyError:
            node = self.Node(key, value, self._t)
            self._dict[key] = node
            if len(self) < self.size:
                heappush(self._heap, node)
            else:
                old = heapreplace(self._heap, node)
                del self._dict[old.key]

    def __getitem__(self, key):
        node = self._dict[key]
        self[key] = node.value
        return node.value

    def __delitem__(self, key):
        node = self._dict[key]
        del self._dict[key]
        self._heap.remove(node)
        heapify(self._heap)

    def __iter__(self):
        copy = self._heap[:]
        while copy:
            yield heappop(copy).key

    def iteritems(self):
        copy = self._heap[:]
        while copy:
            node = heappop(copy)
            yield node.key, node.value

    def keys(self):
        return self._dict.keys()

    def __contains__(self, key):
        return key in self._dict

    def __len__(self):
        return len(self._heap)


class LRUCacheTestCase(unittest.TestCase):

    def test(self):
        c = LRUCache(2)
        self.assertEqual(len(c), 0)
        for i, x in enumerate('abc'):
            c[x] = i
        self.assertEqual(len(c), 2)
        self.assertEqual(list(c), ['b', 'c'])
        self.assertEqual(list(c.iteritems()), [('b', 1), ('c', 2)])
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

