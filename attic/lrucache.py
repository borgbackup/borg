class LRUCache(dict):

    def __init__(self, capacity, dispose):
        super(LRUCache, self).__init__()
        self._lru = []
        self._capacity = capacity
        self._dispose = dispose

    def __setitem__(self, key, value):
        assert key not in self, (
            "Unexpected attempt to replace a cached item."
            " If this is intended, please delete or pop the old item first."
            " The dispose function will be called on delete (but not pop).")
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
        error = KeyError(key)
        removed = super(LRUCache, self).pop(key, error)
        if removed == error:
            raise error
        self._dispose(removed)

    def pop(self, key, default=None):
        try:
            self._lru.remove(key)
        except ValueError:
            pass
        return super(LRUCache, self).pop(key, default)

    def clear(self):
        for value in self.values():
            self._dispose(value)
        super(LRUCache, self).clear()

    def _not_implemented(self, *args, **kw):
        raise NotImplementedError
    popitem = setdefault = update = _not_implemented
