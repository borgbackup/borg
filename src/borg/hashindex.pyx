from collections import namedtuple

cimport cython
from libc.stdint cimport uint32_t, UINT32_MAX, uint64_t

from borghash cimport _borghash

API_VERSION = '1.2_01'


cdef extern from "_hashindex.c":
    ctypedef struct HashIndex:
        pass

    HashIndex *hashindex_read(object file_py, int permit_compact, int legacy) except *
    HashIndex *hashindex_init(int capacity, int key_size, int value_size)
    void hashindex_free(HashIndex *index)
    int hashindex_len(HashIndex *index)
    int hashindex_size(HashIndex *index)
    void hashindex_write(HashIndex *index, object file_py, int legacy) except *
    unsigned char *hashindex_get(HashIndex *index, unsigned char *key)
    unsigned char *hashindex_next_key(HashIndex *index, unsigned char *key)
    int hashindex_delete(HashIndex *index, unsigned char *key)
    int hashindex_set(HashIndex *index, unsigned char *key, void *value)
    uint64_t hashindex_compact(HashIndex *index)
    uint32_t _htole32(uint32_t v)
    uint32_t _le32toh(uint32_t v)

    double HASH_MAX_LOAD


_MAX_VALUE = 4294966271UL  # 2**32 - 1025

cdef _NoDefault = object()

"""
The HashIndex is *not* a general purpose data structure. The value size must be at least 4 bytes, and these
first bytes are used for in-band signalling in the data structure itself.

The constant MAX_VALUE defines the valid range for these 4 bytes when interpreted as an uint32_t from 0
to MAX_VALUE (inclusive). The following reserved values beyond MAX_VALUE are currently in use
(byte order is LE)::

    0xffffffff marks empty entries in the hashtable
    0xfffffffe marks deleted entries in the hashtable

None of the publicly available classes in this module will accept nor return a reserved value;
AssertionError is raised instead.
"""

assert UINT32_MAX == 2**32-1

assert _MAX_VALUE % 2 == 1


def hashindex_variant(fn):
    """peek into an index file and find out what it is"""
    with open(fn, 'rb') as f:
        magic = f.read(8)  # MAGIC_LEN
    if magic == b'BORG_IDX':
        return 1  # legacy
    if magic == b'BORG2IDX':
        return 2
    if magic == b'12345678':  # used by unit tests
        return 2  # just return the current variant
    raise ValueError(f'unknown hashindex magic: {magic!r}')


@cython.internal
cdef class IndexBase:
    cdef HashIndex *index
    cdef int key_size
    legacy = 0

    _key_size = 32

    MAX_LOAD_FACTOR = HASH_MAX_LOAD
    MAX_VALUE = _MAX_VALUE

    def __cinit__(self, capacity=0, path=None, permit_compact=False, usable=None):
        self.key_size = self._key_size
        if path:
            if isinstance(path, (str, bytes)):
                with open(path, 'rb') as fd:
                    self.index = hashindex_read(fd, permit_compact, self.legacy)
            else:
                self.index = hashindex_read(path, permit_compact, self.legacy)
            assert self.index, 'hashindex_read() returned NULL with no exception set'
        else:
            if usable is not None:
                capacity = int(usable / self.MAX_LOAD_FACTOR)
            self.index = hashindex_init(capacity, self.key_size, self.value_size)
            if not self.index:
                raise Exception('hashindex_init failed')

    def __dealloc__(self):
        if self.index:
            hashindex_free(self.index)

    @classmethod
    def read(cls, path, permit_compact=False):
        return cls(path=path, permit_compact=permit_compact)

    def write(self, path):
        if isinstance(path, (str, bytes)):
            with open(path, 'wb') as fd:
                hashindex_write(self.index, fd, self.legacy)
        else:
            hashindex_write(self.index, path, self.legacy)

    def clear(self):
        hashindex_free(self.index)
        self.index = hashindex_init(0, self.key_size, self.value_size)
        if not self.index:
            raise Exception('hashindex_init failed')

    def setdefault(self, key, value):
        if not key in self:
            self[key] = value
        return self[key]

    def __delitem__(self, key):
        assert len(key) == self.key_size
        rc = hashindex_delete(self.index, <unsigned char *>key)
        if rc == 1:
            return  # success
        if rc == -1:
            raise KeyError(key)
        if rc == 0:
            raise Exception('hashindex_delete failed')

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

    def __len__(self):
        return hashindex_len(self.index)

    def size(self):
        """Return size (bytes) of hash table."""
        return hashindex_size(self.index)

    def compact(self):
        return hashindex_compact(self.index)


NSIndexEntry = namedtuple('NSIndexEntry', 'segment offset size')


cdef class NSIndex(IndexBase):

    value_size = 12

    def __getitem__(self, key):
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        cdef uint32_t segment = _le32toh(data[0])
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return NSIndexEntry(segment, _le32toh(data[1]), _le32toh(data[2]))

    def __setitem__(self, key, value):
        assert len(key) == self.key_size
        cdef uint32_t[3] data
        assert len(value) == len(data)
        cdef uint32_t segment = value[0]
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        data[0] = _htole32(segment)
        data[1] = _htole32(value[1])
        data[2] = _htole32(value[2])
        if not hashindex_set(self.index, <unsigned char *>key, data):
            raise Exception('hashindex_set failed')

    def __contains__(self, key):
        cdef uint32_t segment
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if data != NULL:
            segment = _le32toh(data[0])
            assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return data != NULL

    def iteritems(self, marker=None):
        """iterate over all items or optionally only over items having specific flag values"""
        cdef const unsigned char *key
        iter = NSKeyIterator(self.key_size)
        iter.idx = self
        iter.index = self.index
        if marker:
            key = hashindex_get(self.index, <unsigned char *>marker)
            if marker is None:
                raise IndexError
            iter.key = key - self.key_size
        return iter


cdef class NSKeyIterator:
    cdef NSIndex idx
    cdef HashIndex *index
    cdef const unsigned char *key
    cdef int key_size
    cdef int exhausted

    def __cinit__(self, key_size):
        self.key = NULL
        self.key_size = key_size
        self.exhausted = 0

    def __iter__(self):
        return self

    def __next__(self):
        cdef uint32_t *value
        if self.exhausted:
            raise StopIteration
        self.key = hashindex_next_key(self.index, <unsigned char *>self.key)
        if not self.key:
            self.exhausted = 1
            raise StopIteration
        value = <uint32_t *> (self.key + self.key_size)
        cdef uint32_t segment = _le32toh(value[0])
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return ((<char *>self.key)[:self.key_size],
                NSIndexEntry(segment, _le32toh(value[1]), _le32toh(value[2])))


cdef class NSIndex1(IndexBase):  # legacy borg 1.x

    legacy = 1
    value_size = 8

    def __getitem__(self, key):
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        cdef uint32_t segment = _le32toh(data[0])
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return segment, _le32toh(data[1])

    def __setitem__(self, key, value):
        assert len(key) == self.key_size
        cdef uint32_t[2] data
        cdef uint32_t segment = value[0]
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        data[0] = _htole32(segment)
        data[1] = _htole32(value[1])
        if not hashindex_set(self.index, <unsigned char *>key, data):
            raise Exception('hashindex_set failed')

    def __contains__(self, key):
        cdef uint32_t segment
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if data != NULL:
            segment = _le32toh(data[0])
            assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return data != NULL

    def iteritems(self, marker=None):
        cdef const unsigned char *key
        iter = NSKeyIterator1(self.key_size)
        iter.idx = self
        iter.index = self.index
        if marker:
            key = hashindex_get(self.index, <unsigned char *>marker)
            if marker is None:
                raise IndexError
            iter.key = key - self.key_size
        return iter


cdef class NSKeyIterator1:  # legacy borg 1.x
    cdef NSIndex1 idx
    cdef HashIndex *index
    cdef const unsigned char *key
    cdef int key_size
    cdef int exhausted

    def __cinit__(self, key_size):
        self.key = NULL
        self.key_size = key_size
        self.exhausted = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.exhausted:
            raise StopIteration
        self.key = hashindex_next_key(self.index, <unsigned char *>self.key)
        if not self.key:
            self.exhausted = 1
            raise StopIteration
        cdef uint32_t *value = <uint32_t *>(self.key + self.key_size)
        cdef uint32_t segment = _le32toh(value[0])
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return (<char *>self.key)[:self.key_size], (segment, _le32toh(value[1]))


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
        pass

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
