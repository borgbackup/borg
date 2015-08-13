class _NotFound:
    pass

class LRUCache:
    def __init__(self, capacity, dispose):
        self._cache = {}
        self._lru = []
        self._capacity = capacity
        self._dispose = dispose

    def __setitem__(self, key, value):
        assert key not in self._cache, (
            "Unexpected attempt to replace a cached item,"
            " without first deleting the old item.")
        self._lru.append(key)
        while len(self._lru) > self._capacity:
            del self[self._lru[0]]
        self._cache[key] = value

    def __getitem__(self, key):
        try:
            self._lru.remove(key)
            self._lru.append(key)
        except ValueError:
            pass
        return self._cache[key]

    def __delitem__(self, key):
        try:
            self._lru.remove(key)
        except ValueError:
            pass
        item = self._cache.pop(key, _NotFound)
        if item is _NotFound:
            raise KeyError(key)
        self._dispose(item)

    def __contains__(self, key):
        return key in self._cache

    def clear(self):
        for value in self._cache.values():
            self._dispose(value)
        self._cache.clear()

    # useful for testing
    def items(self):
        return self._cache.items()

    def __len__(self):
        return len(self._cache)
