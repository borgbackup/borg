from collections import OrderedDict
from collections.abc import Callable, ItemsView, Iterator, KeysView, MutableMapping, ValuesView
from typing import TypeVar

K = TypeVar("K")
V = TypeVar("V")


class LRUCache(MutableMapping[K, V]):
    """
    Mapping which maintains a maximum size by removing the least recently used value.
    Items are passed to dispose before being removed and setting an item which is
    already in the cache has to be done using the replace method.
    """

    _cache: OrderedDict[K, V]

    _capacity: int

    _dispose: Callable[[V], None]

    def __init__(self, capacity: int, dispose: Callable[[V], None] = lambda _: None):
        self._cache = OrderedDict()
        self._capacity = capacity
        self._dispose = dispose

    def __setitem__(self, key: K, value: V) -> None:
        assert key not in self._cache, (
            "Unexpected attempt to replace a cached item," " without first deleting the old item."
        )
        while len(self._cache) >= self._capacity:
            self._dispose(self._cache.popitem(last=False)[1])
        self._cache[key] = value
        self._cache.move_to_end(key)

    def __getitem__(self, key: K) -> V:
        self._cache.move_to_end(key)  # raise KeyError if not found
        return self._cache[key]

    def __delitem__(self, key: K) -> None:
        self._dispose(self._cache.pop(key))

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def replace(self, key: K, value: V) -> None:
        """Replace an item which is already present, not disposing it in the process"""
        # this method complements __setitem__ which should be used for the normal use case.
        assert key in self._cache, "Unexpected attempt to update a non-existing item."
        self._cache[key] = value

    def clear(self) -> None:
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
