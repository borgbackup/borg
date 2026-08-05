from tempfile import TemporaryFile

import pytest

from ...helpers.lrucache import LRUCache


class TestLRUCache:
    def test_lrucache(self):
        c = LRUCache(2)
        assert len(c) == 0
        assert c.items() == set()
        for i, x in enumerate("abc"):
            c[x] = i
        assert len(c) == 2
        assert c.items() == {("b", 1), ("c", 2)}
        assert "a" not in c
        assert "b" in c
        with pytest.raises(KeyError):
            c["a"]
        assert c.get("a") is None
        assert c.get("a", "foo") == "foo"
        assert c["b"] == 1
        assert c.get("b") == 1
        assert c["c"] == 2
        c["d"] = 3
        assert len(c) == 2
        assert c["c"] == 2
        assert c["d"] == 3
        del c["c"]
        assert len(c) == 1
        with pytest.raises(KeyError):
            c["c"]
        assert c["d"] == 3
        c.clear()
        assert c.items() == set()

    def test_assign_to_existing_key(self):
        # assigning to a key that is present replaces the value and counts as a use,
        # so the entry becomes the most recently used one.
        c = LRUCache(2)
        c["a"] = 1
        c["b"] = 2
        c["a"] = 3  # replaces, and refreshes "a"
        assert len(c) == 2
        assert c["a"] == 3
        c["c"] = 4  # evicts the least recently used entry, which is "b" now
        assert set(c.keys()) == {"a", "c"}

    def test_dispose_on_replacement(self):
        disposed = []
        c = LRUCache(2, dispose=disposed.append)
        c["a"] = "first"
        c["a"] = "second"  # the replaced value leaves the cache, so it is disposed
        assert disposed == ["first"]
        assert c["a"] == "second"
        value = "same object"
        c["b"] = value
        c["b"] = value  # assigning the identical object does not dispose it
        assert disposed == ["first"]
        c.replace("b", "replacement")  # replace() never disposes, see there
        assert disposed == ["first"]
        assert c["b"] == "replacement"

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
