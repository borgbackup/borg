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

    def pop(self, key, default=None):
        try:
            self._lru.remove(key)
        except ValueError:
            pass
        return super(LRUCache, self).pop(key, default)

    def _not_implemented(self, *args, **kw):
        raise NotImplementedError
    popitem = setdefault = update = _not_implemented
