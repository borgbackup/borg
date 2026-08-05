import threading
from collections import OrderedDict
from collections.abc import Callable, ItemsView, Iterator, KeysView, MutableMapping, ValuesView
from typing import Any, TypeVar

K = TypeVar("K")
V = TypeVar("V")

_MISSING = object()


class LRUCache(MutableMapping[K, V]):
    """
    Mapping which maintains a maximum size by removing the least recently used value.

    A value that leaves the cache - evicted, deleted, or replaced by another value under
    the same key - is passed to *dispose* first, so that a cache of e.g. open files can
    close them. Use replace() to update an entry while keeping its old value alive.

    Thread safety: getting, setting, deleting, popping, replacing and clearing are each
    atomic, so several threads can share one cache without corrupting it. A *sequence* of
    them is not: two threads can miss on the same key and both compute and store a value,
    which for a cache is wasteful, not wrong - and the mixin methods built on top of the
    above (setdefault, popitem, update) inherit that. Iterating (also via keys(), values(),
    items()) yields a live view of the underlying dict, so it needs external
    synchronization if another thread may write meanwhile.

    *dispose* is called while the lock is held, so it must not use the cache.
    """

    _cache: OrderedDict[K, V]

    _capacity: int

    _dispose: Callable[[V], None]

    def __init__(self, capacity: int, dispose: Callable[[V], None] = lambda _: None):
        self._cache = OrderedDict()
        self._capacity = capacity
        self._dispose = dispose
        self._lock = threading.Lock()

    def __setitem__(self, key: K, value: V) -> None:
        with self._lock:
            try:
                previous = self._cache.pop(key)
            except KeyError:
                pass
            else:
                # the old value is no longer in the cache, so it is disposed like a deleted one.
                if previous is not value:
                    self._dispose(previous)
            while len(self._cache) >= self._capacity:
                self._dispose(self._cache.popitem(last=False)[1])
            self._cache[key] = value  # add the new (or refreshed) entry at the end

    def __getitem__(self, key: K) -> V:
        with self._lock:
            self._cache.move_to_end(key)  # raise KeyError if not found
            return self._cache[key]

    def __delitem__(self, key: K) -> None:
        with self._lock:
            self._dispose(self._cache.pop(key))

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def pop(self, key: K, default: Any = _MISSING) -> Any:
        """Remove *key* and return its value, without disposing it."""
        # MutableMapping would implement this as __getitem__ + __delitem__, which is not
        # atomic (and would dispose the value).
        with self._lock:
            try:
                return self._cache.pop(key)
            except KeyError:
                if default is _MISSING:
                    raise
                return default

    def replace(self, key: K, value: V) -> None:
        """Replace the value of an entry that is present, without disposing the old value.

        This is for the rare case where the old value must stay alive, e.g. because the new
        value still refers to it (the legacy repository's fd cache re-times-stamps its
        entries this way, keeping the open file object). It also keeps the entry where it
        is in the LRU order, i.e. it does not count as a use. Everything else should just
        assign to the cache.
        """
        with self._lock:
            assert key in self._cache, "Unexpected attempt to update a non-existing item."
            self._cache[key] = value

    def clear(self) -> None:
        with self._lock:
            for value in self._cache.values():
                self._dispose(value)
            self._cache.clear()

    def __iter__(self) -> Iterator[K]:
        return iter(self._cache)

    def keys(self) -> KeysView[K]:
        return self._cache.keys()

    def values(self) -> ValuesView[V]:
        return self._cache.values()

    def items(self) -> ItemsView[K, V]:
        return self._cache.items()
