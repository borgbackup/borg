class LRUCache:
    def __init__(self, capacity, dispose):
        self._cache = {}
        self._lru = []
        self._capacity = capacity
        self._dispose = dispose

    def __setitem__(self, key, value):
        assert key not in self._cache, (
            "Unexpected attempt to replace a cached item."
            " If this is intended, please delete the old item first."
            " The dispose function will be called on delete.")
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
        error = KeyError(key)
        removed = self._cache.pop(key, error)
        if removed == error:
            raise error
        self._dispose(removed)

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
