sentinel = object()


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
        value = self._cache[key]  # raise KeyError if not found
        self._lru.remove(key)
        self._lru.append(key)
        return value

    def __delitem__(self, key):
        value = self._cache.pop(key)  # raise KeyError if not found
        self._dispose(value)
        self._lru.remove(key)

    def __contains__(self, key):
        return key in self._cache

    def get(self, key, default=None):
        value = self._cache.get(key, sentinel)
        if value is sentinel:
            return default
        self._lru.remove(key)
        self._lru.append(key)
        return value

    def clear(self):
        for value in self._cache.values():
            self._dispose(value)
        self._cache.clear()

    # useful for testing
    def items(self):
        return self._cache.items()

    def __len__(self):
        return len(self._cache)
