from collections.abc import MutableMapping
from collections import namedtuple
import os
import struct

from borghash import HashTableNT

from .constants import UNKNOWN_INT32, UNKNOWN_BYTES32



cdef _NoDefault = object()


class HTProxyMixin:
    def __setitem__(self, key, value):
        self.ht[key] = value

    def __getitem__(self, key):
        return self.ht[key]

    def __delitem__(self, key):
        del self.ht[key]

    def __contains__(self, key):
        return key in self.ht

    def __len__(self):
        return len(self.ht)

    def __iter__(self):
        for key, value in self.ht.items():
            yield key

    def clear(self):
        self.ht.clear()


ChunkIndexEntry = namedtuple('ChunkIndexEntry', 'flags size pack_id obj_offset obj_size')
ChunkIndexEntryFormatT = namedtuple('ChunkIndexEntryFormatT', 'flags size pack_id obj_offset obj_size')
ChunkIndexEntryFormat = ChunkIndexEntryFormatT(flags="I", size="I", pack_id="32s", obj_offset="I", obj_size="I")


class ChunkIndex(HTProxyMixin, MutableMapping):
    """
    Mapping from key256 to (flags32, size32, pack_id256, obj_offset32, obj_size32) to track chunks in the repository.
    """
    # .flags related values:
    F_NONE = 0  # all flags cleared
    M_USER = 0x00ffffff  # mask for user flags
    M_SYSTEM = 0xff000000  # mask for system flags
    # user flags:
    F_USED = 2 ** 0  # chunk is used/referenced
    F_COMPRESS = 2 ** 1  # chunk shall get (re-)compressed
    F_PENDING = 2 ** 2  # pack location (pack_id, obj_offset, obj_size) not resolved yet.
    # system flags (internal use, always 0 to user, not changeable by user):
    F_NEW = 2 ** 24  # a new chunk that is not present in repo index/* yet.

    def __init__(self, capacity=1000, path=None, usable=None):
        if path:
            self.ht = HashTableNT.read(path)
            self._new_count = None  # unknown, computed lazily (see new_count)
        else:
            if usable is not None:
                capacity = usable * 2  # load factor 0.5
            self.ht = HashTableNT(key_size=32, value_type=ChunkIndexEntry, value_format=ChunkIndexEntryFormat,
                                  capacity=capacity)
            self._new_count = 0

    def hide_system_flags(self, value):
        user_flags = value.flags & self.M_USER
        return value._replace(flags=user_flags)

    @property
    def new_count(self):
        """Count of new entries (entries that have the F_NEW flag set)."""
        if self._new_count is None:
            # loaded from a file: compute once, then maintain incrementally.
            self._new_count = sum(1 for key, value in self.ht.items() if value.flags & self.F_NEW)
        return self._new_count

    def iteritems(self, *, only_new=False, prefix_bits=0, prefix=0):
        """
        Iterates items (optionally only new items and/or only items of one key-prefix partition);
        hides system flags.

        See borghash.HashTable.items for the prefix_bits / prefix semantics.
        """
        for key, value in self.ht.items(prefix_bits=prefix_bits, prefix=prefix):
            if not only_new or (value.flags & self.F_NEW):
                yield key, self.hide_system_flags(value)

    def add(self, key, size):
        v = self.get(key)
        if v is None:
            flags = self.F_USED
        else:
            flags = v.flags | self.F_USED
            assert v.size == 0 or v.size == size
        # F_PENDING marks the pack location (pack_id, obj_offset, obj_size) as not yet set.
        # Re-adding a chunk resets it to UNKNOWN/pending, dropping any prior location until the next flush().
        self[key] = ChunkIndexEntry(
            flags=flags | self.F_PENDING, size=size,
            pack_id=UNKNOWN_BYTES32, obj_offset=UNKNOWN_INT32, obj_size=UNKNOWN_INT32
        )

    def __getitem__(self, key):
        """Specialized __getitem__ that hides system flags."""
        value = self.ht[key]
        return self.hide_system_flags(value)

    def __setitem__(self, key, value):
        """Specialized __setitem__ that protects system flags and manages the F_NEW flag."""
        try:
            prev = self.ht[key]
        except KeyError:
            prev_flags = self.F_NONE
            is_new = True
            inserting = True
        else:
            prev_flags = prev.flags
            is_new = bool(prev_flags & self.F_NEW)  # was new? stays new!
            inserting = False
        system_flags = prev_flags & self.M_SYSTEM
        if is_new:
            system_flags |= self.F_NEW
        else:
            system_flags &= ~self.F_NEW
        user_flags = value.flags & self.M_USER
        self.ht[key] = value._replace(flags=system_flags | user_flags)
        if inserting and self._new_count is not None:
            self._new_count += 1  # inserted a new entry (overwriting keeps the F_NEW state)

    def __delitem__(self, key):
        value = self.ht.pop(key)  # raises KeyError if not present, like del would
        if self._new_count is not None and (value.flags & self.F_NEW):
            self._new_count -= 1

    def clear(self):
        self.ht.clear()
        self._new_count = 0

    def update_pack_info(self, pack_results):
        """Set pack_id, obj_offset and obj_size from a list of (chunk_id, pack_id, obj_offset, obj_size)
        tuples and clear F_PENDING."""
        if not pack_results:
            return
        for chunk_id, pack_id, obj_offset, obj_size in pack_results:
            existing = self[chunk_id]
            self[chunk_id] = existing._replace(
                flags=existing.flags & ~self.F_PENDING, pack_id=pack_id, obj_offset=obj_offset, obj_size=obj_size
            )

    def is_pending(self, key):
        """Return whether the chunk's pack location (pack_id, obj_offset, obj_size) is unresolved."""
        return bool(self[key].flags & self.F_PENDING)

    def clear_new(self):
        """Clears the F_NEW flag of all items."""
        for key, value in self.ht.items():
            if value.flags & self.F_NEW:
                flags = value.flags & ~self.F_NEW
                self.ht[key] = value._replace(flags=flags)
        self._new_count = 0

    @classmethod
    def read(cls, path):
        return cls(path=path)

    def write(self, path):
        self.ht.write(path)

    def size(self):
        return self.ht.size()

    @property
    def stats(self):
        return self.ht.stats

    def k_to_idx(self, key):
        return self.ht.k_to_idx(key)

    def idx_to_k(self, idx):
        return self.ht.idx_to_k(idx)


FuseVersionsIndexEntry = namedtuple('FuseVersionsIndexEntry', 'version hash')
FuseVersionsIndexEntryFormatT = namedtuple('FuseVersionsIndexEntryFormatT', 'version hash')
FuseVersionsIndexEntryFormat = FuseVersionsIndexEntryFormatT(version="I", hash="16s")


class FuseVersionsIndex(HTProxyMixin, MutableMapping):
    """
    Mapping from key128 to (file_version32, file_content_hash128) to support the FUSE versions view.
    """
    def __init__(self):
        self.ht = HashTableNT(key_size=16, value_type=FuseVersionsIndexEntry, value_format=FuseVersionsIndexEntryFormat)
