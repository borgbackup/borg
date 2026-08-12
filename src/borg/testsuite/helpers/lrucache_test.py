import sys
import threading
import time
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

    def test_pop(self):
        disposed = []
        c = LRUCache(2, dispose=disposed.append)
        c["a"] = 1
        assert c.pop("a") == 1  # pop hands the value to the caller, so it is not disposed
        assert disposed == []
        assert "a" not in c
        assert c.pop("a", "default") == "default"
        with pytest.raises(KeyError):
            c.pop("a")

    def test_threaded_access(self):
        # several threads sharing one cache must not corrupt it or raise: they hit the same
        # keys, so they race on inserting, refreshing, evicting and removing the same entries.
        # e.g. popping via MutableMapping (get, then delete) raises KeyError here when
        # another thread removes the key in between.
        c: LRUCache = LRUCache(8)
        keys = list(range(16))  # more keys than capacity, so entries keep getting evicted
        errors: list[Exception] = []
        start = threading.Barrier(8)

        # time-bounded instead of a fixed round count: with the tiny switch interval and
        # coverage tracing, a fixed count takes wildly different time across platforms
        # (it ran into the test timeout on a slow NetBSD CI VM).
        deadline = time.monotonic() + 2.0

        def worker(n):
            start.wait()
            try:
                while True:
                    for key in keys:
                        c[key] = n
                        c.get(key)
                        c.pop(key, None)
                    if time.monotonic() >= deadline:
                        break
            except Exception as e:
                errors.append(e)

        # the default switch interval (5 ms) is longer than these loops, so threads would
        # hardly ever switch inside one cache operation and the races would not show up.
        previous_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(previous_interval)
        assert errors == []
        assert len(c) <= 8
