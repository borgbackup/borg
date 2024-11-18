from collections.abc import MutableMapping
from collections import namedtuple
import os
import struct

from borghash import HashTableNT

API_VERSION = '1.2_01'

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


ChunkIndexEntry = namedtuple('ChunkIndexEntry', 'flags size')
ChunkIndexEntryFormatT = namedtuple('ChunkIndexEntryFormatT', 'flags size')
ChunkIndexEntryFormat = ChunkIndexEntryFormatT(flags="I", size="I")


class ChunkIndex(HTProxyMixin, MutableMapping):
    """
    Mapping from key256 to (flags32, size32) to track chunks in the repository.
    """
    # .flags related values:
    F_NONE = 0  # all flags cleared
    M_USER = 0x00ffffff  # mask for user flags
    M_SYSTEM = 0xff000000  # mask for system flags
    # user flags:
    F_USED = 2 ** 0  # chunk is used/referenced
    F_COMPRESS = 2 ** 1  # chunk shall get (re-)compressed
    # system flags (internal use, always 0 to user, not changeable by user):
    F_NEW = 2 ** 24  # a new chunk that is not present in repo/cache/chunks.* yet.

    def __init__(self, capacity=1000, path=None, usable=None):
        if path:
            self.ht = HashTableNT.read(path)
        else:
            if usable is not None:
                capacity = usable * 2  # load factor 0.5
            self.ht = HashTableNT(key_size=32, value_type=ChunkIndexEntry, value_format=ChunkIndexEntryFormat,
                                  capacity=capacity)

    def hide_system_flags(self, value):
        user_flags = value.flags & self.M_USER
        return value._replace(flags=user_flags)

    def iteritems(self, *, only_new=False):
        """iterate items (optionally only new items), hide system flags."""
        for key, value in self.ht.items():
            if not only_new or (value.flags & self.F_NEW):
                yield key, self.hide_system_flags(value)

    def add(self, key, size):
        v = self.get(key)
        if v is None:
            flags = self.F_USED
        else:
            flags = v.flags | self.F_USED
            assert v.size == 0 or v.size == size
        self[key] = ChunkIndexEntry(flags=flags, size=size)

    def __getitem__(self, key):
        """specialized __getitem__ that hides system flags."""
        value = self.ht[key]
        return self.hide_system_flags(value)

    def __setitem__(self, key, value):
        """specialized __setitem__ that protects system flags, manages F_NEW flag."""
        try:
            prev = self.ht[key]
        except KeyError:
            prev_flags = self.F_NONE
            is_new = True
        else:
            prev_flags = prev.flags
            is_new = bool(prev_flags & self.F_NEW)  # was new? stays new!
        system_flags = prev_flags & self.M_SYSTEM
        if is_new:
            system_flags |= self.F_NEW
        else:
            system_flags &= ~self.F_NEW
        user_flags = value.flags & self.M_USER
        self.ht[key] = value._replace(flags=system_flags | user_flags)

    def clear_new(self):
        """clear F_NEW flag of all items"""
        for key, value in self.ht.items():
            if value.flags & self.F_NEW:
                flags = value.flags & ~self.F_NEW
                self.ht[key] = value._replace(flags=flags)

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


NSIndex1Entry = namedtuple('NSIndex1Entry', 'segment offset')
NSIndex1EntryFormatT = namedtuple('NSIndex1EntryFormatT', 'segment offset')
NSIndex1EntryFormat = NSIndex1EntryFormatT(segment="I", offset="I")


class NSIndex1(HTProxyMixin, MutableMapping):
    """
    Mapping from key256 to (segment32, offset32), as used by legacy repo index of borg 1.x.
    """
    MAX_VALUE = 2**32 - 1  # borghash has the full uint32_t range
    MAGIC = b"BORG_IDX"  # borg 1.x
    HEADER_FMT = "<8sIIBB"  # magic, entries, buckets, ksize, vsize
    KEY_SIZE = 32
    VALUE_SIZE = 8

    def __init__(self, capacity=1000, path=None, usable=None):
        if usable is not None:
            capacity = usable * 2  # load factor 0.5
        self.ht = HashTableNT(key_size=self.KEY_SIZE, value_type=NSIndex1Entry, value_format=NSIndex1EntryFormat,
                              capacity=capacity)
        if path:
            self._read(path)

    def iteritems(self, marker=None):
        do_yield = marker is None
        for key, value in self.ht.items():
            if do_yield:
                yield key, value
            else:
                do_yield = key == marker

    @classmethod
    def read(cls, path):
        return cls(path=path)

    def size(self):
        return self.ht.size()  # not quite correct as this is not the on-disk read-only format.

    def write(self, path):
        if isinstance(path, str):
            with open(path, 'wb') as fd:
                self._write_fd(fd)
        else:
            self._write_fd(path)

    def _read(self, path):
        if isinstance(path, str):
            with open(path, 'rb') as fd:
                self._read_fd(fd)
        else:
            self._read_fd(path)

    def _write_fd(self, fd):
        used = len(self.ht)
        header_bytes = struct.pack(self.HEADER_FMT, self.MAGIC, used, used, self.KEY_SIZE, self.VALUE_SIZE)
        fd.write(header_bytes)
        count = 0
        for key, _ in self.ht.items():
            value = self.ht._get_raw(key)
            fd.write(key)
            fd.write(value)
            count += 1
        assert count == used

    def _read_fd(self, fd):
        header_size = struct.calcsize(self.HEADER_FMT)
        header_bytes = fd.read(header_size)
        if len(header_bytes) < header_size:
            raise ValueError(f"Invalid file, file is too short (header).")
        magic, entries, buckets, ksize, vsize = struct.unpack(self.HEADER_FMT, header_bytes)
        if magic != self.MAGIC:
            raise ValueError(f"Invalid file, magic {self.MAGIC.decode()} not found.")
        assert ksize == self.KEY_SIZE, "invalid key size"
        assert vsize == self.VALUE_SIZE, "invalid value size"
        buckets_size = buckets * (ksize + vsize)
        current_pos = fd.tell()
        end_of_file = fd.seek(0, os.SEEK_END)
        if current_pos + buckets_size != end_of_file:
            raise ValueError(f"Invalid file, file size does not match (buckets).")
        fd.seek(current_pos)
        for i in range(buckets):
            key = fd.read(ksize)
            value = fd.read(vsize)
            self.ht._set_raw(key, value)
        pos = fd.tell()
        assert pos == end_of_file
