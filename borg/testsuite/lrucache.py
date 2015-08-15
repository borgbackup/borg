from ..lrucache import LRUCache
import pytest
from tempfile import TemporaryFile


class TestLRUCache:

    def test_lrucache(self):
        c = LRUCache(2, dispose=lambda _: None)
        assert len(c) == 0
        assert c.items() == set()
        for i, x in enumerate('abc'):
            c[x] = i
        assert len(c) == 2
        assert c.items() == set([('b', 1), ('c', 2)])
        assert 'a' not in c
        assert 'b' in c
        with pytest.raises(KeyError):
            c['a']
        assert c['b'] == 1
        assert c['c'] == 2
        c['d'] = 3
        assert len(c) == 2
        assert c['c'] == 2
        assert c['d'] == 3
        del c['c']
        assert len(c) == 1
        with pytest.raises(KeyError):
            c['c']
        assert c['d'] == 3
        c.clear()
        assert c.items() == set()

    def test_dispose(self):
        c = LRUCache(2, dispose=lambda f: f.close())
        f1 = TemporaryFile()
        f2 = TemporaryFile()
        f3 = TemporaryFile()
        c[1] = f1
        c[2] = f2
        assert not f2.closed
        c[3] = f3
        assert 1 not in c
        assert f1.closed
        assert 2 in c
        assert not f2.closed
        del c[2]
        assert 2 not in c
        assert f2.closed
        c.clear()
        assert c.items() == set()
        assert f3.closed
