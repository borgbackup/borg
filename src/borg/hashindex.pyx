from collections import namedtuple
import os
import struct

cimport cython

from borghash cimport _borghash

API_VERSION = '1.2_01'

cdef _NoDefault = object()

_MAX_VALUE = 4294966271UL  # 2**32 - 1025
assert _MAX_VALUE % 2 == 1


ChunkIndexEntry = namedtuple('ChunkIndexEntry', 'refcount size')


class ChunkIndex:
    """
    Mapping of 32 byte keys to (refcount, size), which are all 32-bit unsigned.
    """
    MAX_VALUE = 2**32 - 1  # borghash has the full uint32_t range

    def __init__(self, capacity=1000, path=None, permit_compact=False, usable=None):
        if path:
            self.ht = _borghash.HashTableNT.read(path)
        else:
            if usable is not None:
                capacity = usable * 2  # load factor 0.5
            self.ht = _borghash.HashTableNT(key_size=32, value_format="<II", namedtuple_type=ChunkIndexEntry, capacity=capacity)

    def __setitem__(self, key, value):
        if not isinstance(value, ChunkIndexEntry) and isinstance(value, tuple):
            value = ChunkIndexEntry(*value)
        self.ht[key] = value

    def __getitem__(self, key):
        return self.ht[key]

    def __delitem__(self, key):
        del self.ht[key]

    def __contains__(self, key):
        return key in self.ht

    def __len__(self):
        return len(self.ht)

    def iteritems(self):
        yield from self.ht.iteritems()

    def add(self, key, refs, size):
        v = self.get(key, ChunkIndexEntry(0, 0))
        refcount = min(self.MAX_VALUE, v.refcount + refs)
        self[key] = v._replace(refcount=refcount, size=size)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def compact(self):
        return 0

    def clear(self):
        pass

    @classmethod
    def read(cls, path, permit_compact=False):
        return cls(path=path)

    def write(self, path):
        self.ht.write(path)

    def size(self):
        return self.ht.size()


FuseVersionsIndexEntry = namedtuple('FuseVersionsEntry', 'version hash')


class FuseVersionsIndex:
    # key: 16 bytes, value: 4 byte version + 16 bytes file contents hash

    def __init__(self):
        self.ht = _borghash.HashTableNT(key_size=16, value_format="<I16s", namedtuple_type=FuseVersionsIndexEntry)

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

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


NSIndex1Entry = namedtuple('NSIndex1bEntry', 'segment offset')


class NSIndex1:  # legacy borg 1.x

    MAX_VALUE = 2**32 - 1  # borghash has the full uint32_t range

    def __init__(self, capacity=1000, path=None, permit_compact=False, usable=None):
        if usable is not None:
            capacity = usable * 2  # load factor 0.5
        self.ht = _borghash.HashTableNT(key_size=32, value_format="<II", namedtuple_type=NSIndex1Entry, capacity=capacity)
        if path:
            self._read(path)

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

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key, default=_NoDefault):
        try:
            value = self[key]
            del self[key]
            return value
        except KeyError:
            if default != _NoDefault:
                return default
            raise

    def iteritems(self):
        yield from self.ht.iteritems()

    def compact(self):
        return 0

    def clear(self):
        pass

    @classmethod
    def read(cls, path, permit_compact=False):
        return cls(path=path)

    def write(self, path):
        self.ht.write(path)  # only for unit tests

    def size(self):
        return self.ht.size()  # not quite correct as this is not the on-disk read-only format.

    def _read(self, path):
        if isinstance(path, str):
            with open(path, 'rb') as fd:
                self._read_fd(fd)
        else:
            self._read_fd(path)

    def _read_fd(self, fd):
        magic = fd.read(8)
        fd.seek(0)
        if magic == b"BORG_IDX":  # used for borg transfer borg 1.x -> borg 2
            self._read_fd_borg1(fd)
        if magic == b"BORGHASH":  # only for unit tests
            self.ht = _borghash.HashTableNT.read(fd)

    def _read_fd_borg1(self, fd):
        MAGIC = b"BORG_IDX"  # borg 1.x
        HEADER_FMT = "<8sIIBB"  # magic, entries, buckets, ksize, vsize
        header_size = struct.calcsize(HEADER_FMT)
        header_bytes = fd.read(header_size)
        if len(header_bytes) < header_size:
            raise ValueError(f"Invalid file, file is too short (header).")
        magic, entries, buckets, ksize, vsize = struct.unpack(HEADER_FMT, header_bytes)
        if magic != MAGIC:
            raise ValueError(f"Invalid file, magic {MAGIC.decode()} not found.")
        VALUE_FMT = "<II"  # borg 1.x on-disk: little-endian segment, offset
        assert ksize == 32, "invalid key size"
        assert vsize == struct.calcsize(VALUE_FMT), "invalid value size"
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
