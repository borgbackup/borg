from collections import namedtuple

cimport cython
from libc.stdint cimport uint32_t, UINT32_MAX, uint64_t
from libc.string cimport memcpy
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize, PyBytes_CheckExact, PyBytes_GET_SIZE, PyBytes_AS_STRING

API_VERSION = '1.2_01'


cdef extern from "_hashindex.c":
    ctypedef struct HashIndex:
        pass

    ctypedef struct FuseVersionsElement:
        uint32_t version
        char hash[16]

    HashIndex *hashindex_read(object file_py, int permit_compact) except *
    HashIndex *hashindex_init(int capacity, int key_size, int value_size)
    void hashindex_free(HashIndex *index)
    int hashindex_len(HashIndex *index)
    int hashindex_size(HashIndex *index)
    void hashindex_write(HashIndex *index, object file_py) except *
    unsigned char *hashindex_get(HashIndex *index, unsigned char *key)
    unsigned char *hashindex_next_key(HashIndex *index, unsigned char *key)
    int hashindex_delete(HashIndex *index, unsigned char *key)
    int hashindex_set(HashIndex *index, unsigned char *key, void *value)
    uint64_t hashindex_compact(HashIndex *index)
    uint32_t _htole32(uint32_t v)
    uint32_t _le32toh(uint32_t v)

    double HASH_MAX_LOAD


cdef extern from "cache_sync/cache_sync.c":
    ctypedef struct CacheSyncCtx:
        pass

    CacheSyncCtx *cache_sync_init(HashIndex *chunks)
    const char *cache_sync_error(const CacheSyncCtx *ctx)
    uint64_t cache_sync_num_files_totals(const CacheSyncCtx *ctx)
    uint64_t cache_sync_num_files_parts(const CacheSyncCtx *ctx)
    uint64_t cache_sync_size_totals(const CacheSyncCtx *ctx)
    uint64_t cache_sync_size_parts(const CacheSyncCtx *ctx)
    int cache_sync_feed(CacheSyncCtx *ctx, void *data, uint32_t length)
    void cache_sync_free(CacheSyncCtx *ctx)

    uint32_t _MAX_VALUE


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
        hh = f.read(18)  # len(HashHeader)
    magic = hh[0:8]
    if magic == b'BORG_IDX':
        key_size = hh[16]
        value_size = hh[17]
        return f'k{key_size}_v{value_size}'
    if magic == b'12345678':  # used by unit tests
        return 'k32_v16'  # just return the current variant
    raise ValueError(f'unknown hashindex format, magic: {magic!r}')


@cython.internal
cdef class IndexBase:
    cdef HashIndex *index
    cdef int key_size

    _key_size = 32

    MAX_LOAD_FACTOR = HASH_MAX_LOAD
    MAX_VALUE = _MAX_VALUE

    def __cinit__(self, capacity=0, path=None, permit_compact=False, usable=None):
        self.key_size = self._key_size
        if path:
            if isinstance(path, (str, bytes)):
                with open(path, 'rb') as fd:
                    self.index = hashindex_read(fd, permit_compact)
            else:
                self.index = hashindex_read(path, permit_compact)
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
                hashindex_write(self.index, fd)
        else:
            hashindex_write(self.index, path)

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


cdef class FuseVersionsIndex(IndexBase):
    # 4 byte version + 16 byte file contents hash
    value_size = 20
    _key_size = 16

    def __getitem__(self, key):
        cdef FuseVersionsElement *data
        assert len(key) == self.key_size
        data = <FuseVersionsElement *>hashindex_get(self.index, <unsigned char *>key)
        if data == NULL:
            raise KeyError(key)
        return _le32toh(data.version), PyBytes_FromStringAndSize(data.hash, 16)

    def __setitem__(self, key, value):
        cdef FuseVersionsElement data
        assert len(key) == self.key_size
        data.version = value[0]
        assert data.version <= _MAX_VALUE, "maximum number of versions reached"
        if not PyBytes_CheckExact(value[1]) or PyBytes_GET_SIZE(value[1]) != 16:
            raise TypeError("Expected bytes of length 16 for second value")
        memcpy(data.hash, PyBytes_AS_STRING(value[1]), 16)
        data.version = _htole32(data.version)
        if not hashindex_set(self.index, <unsigned char *>key, <void *> &data):
            raise Exception('hashindex_set failed')

    def __contains__(self, key):
        assert len(key) == self.key_size
        return hashindex_get(self.index, <unsigned char *>key) != NULL


NSIndexEntry = namedtuple('NSIndexEntry', 'segment offset size')


cdef class NSIndex(IndexBase):

    value_size = 16

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
        cdef uint32_t[4] data
        cdef uint32_t segment = value[0]
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        data[0] = _htole32(segment)
        data[1] = _htole32(value[1])
        data[2] = _htole32(value[2])
        data[3] = 0  # init flags to all cleared
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

    def iteritems(self, marker=None, mask=0, value=0):
        """iterate over all items or optionally only over items having specific flag values"""
        cdef const unsigned char *key
        assert isinstance(mask, int)
        assert isinstance(value, int)
        iter = NSKeyIterator(self.key_size, mask, value)
        iter.idx = self
        iter.index = self.index
        if marker:
            key = hashindex_get(self.index, <unsigned char *>marker)
            if marker is None:
                raise IndexError
            iter.key = key - self.key_size
        return iter

    def flags(self, key, mask=0xFFFFFFFF, value=None):
        """query and optionally set flags"""
        assert len(key) == self.key_size
        assert isinstance(mask, int)
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        flags = _le32toh(data[3])
        if isinstance(value, int):
            new_flags = flags & ~mask  # clear masked bits
            new_flags |= value & mask  # set value bits
            data[3] = _htole32(new_flags)
        return flags & mask # always return previous flags value


cdef class NSKeyIterator:
    cdef NSIndex idx
    cdef HashIndex *index
    cdef const unsigned char *key
    cdef int key_size
    cdef int exhausted
    cdef unsigned int flag_mask
    cdef unsigned int flag_value

    def __cinit__(self, key_size, mask, value):
        self.key = NULL
        self.key_size = key_size
        # note: mask and value both default to 0, so they will match all entries
        self.flag_mask = _htole32(mask)
        self.flag_value = _htole32(value)
        self.exhausted = 0

    def __iter__(self):
        return self

    def __next__(self):
        cdef uint32_t *value
        if self.exhausted:
            raise StopIteration
        while True:
            self.key = hashindex_next_key(self.index, <unsigned char *>self.key)
            if not self.key:
                self.exhausted = 1
                raise StopIteration
            value = <uint32_t *> (self.key + self.key_size)
            if value[3] & self.flag_mask == self.flag_value:
                # we found a matching entry!
                break

        cdef uint32_t segment = _le32toh(value[0])
        assert segment <= _MAX_VALUE, "maximum number of segments reached"
        return ((<char *>self.key)[:self.key_size],
                NSIndexEntry(segment, _le32toh(value[1]), _le32toh(value[2])))


cdef class NSIndex1(IndexBase):  # legacy borg 1.x

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


cdef class ChunkIndex(IndexBase):
    """
    Mapping of 32 byte keys to (refcount, size), which are all 32-bit unsigned.

    The reference count cannot overflow. If an overflow would occur, the refcount
    is fixed to MAX_VALUE and will neither increase nor decrease by incref(), decref()
    or add().

    Prior signed 32-bit overflow is handled correctly for most cases: All values
    from UINT32_MAX (2**32-1, inclusive) to MAX_VALUE (exclusive) are reserved and either
    cause silent data loss (-1, -2) or will raise an AssertionError when accessed.
    Other values are handled correctly. Note that previously the refcount could also reach
    0 by *increasing* it.

    Assigning refcounts in this reserved range is an invalid operation and raises AssertionError.
    """

    value_size = 8

    def __getitem__(self, key):
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        cdef uint32_t refcount = _le32toh(data[0])
        assert refcount <= _MAX_VALUE, "invalid reference count"
        return ChunkIndexEntry(refcount, _le32toh(data[1]))

    def __setitem__(self, key, value):
        assert len(key) == self.key_size
        cdef uint32_t[2] data
        cdef uint32_t refcount = value[0]
        assert refcount <= _MAX_VALUE, "invalid reference count"
        data[0] = _htole32(refcount)
        data[1] = _htole32(value[1])
        if not hashindex_set(self.index, <unsigned char *>key, data):
            raise Exception('hashindex_set failed')

    def __contains__(self, key):
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if data != NULL:
            assert _le32toh(data[0]) <= _MAX_VALUE, "invalid reference count"
        return data != NULL

    def incref(self, key):
        """Increase refcount for 'key', return (refcount, size)"""
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        cdef uint32_t refcount = _le32toh(data[0])
        assert refcount <= _MAX_VALUE, "invalid reference count"
        if refcount != _MAX_VALUE:
            refcount += 1
        data[0] = _htole32(refcount)
        return refcount, _le32toh(data[1])

    def decref(self, key):
        """Decrease refcount for 'key', return (refcount, size)"""
        assert len(key) == self.key_size
        data = <uint32_t *>hashindex_get(self.index, <unsigned char *>key)
        if not data:
            raise KeyError(key)
        cdef uint32_t refcount = _le32toh(data[0])
        # Never decrease a reference count of zero
        assert 0 < refcount <= _MAX_VALUE, "invalid reference count"
        if refcount != _MAX_VALUE:
            refcount -= 1
        data[0] = _htole32(refcount)
        return refcount, _le32toh(data[1])

    def iteritems(self, marker=None):
        cdef const unsigned char *key
        iter = ChunkKeyIterator(self.key_size)
        iter.idx = self
        iter.index = self.index
        if marker:
            key = hashindex_get(self.index, <unsigned char *>marker)
            if marker is None:
                raise IndexError
            iter.key = key - self.key_size
        return iter

    def summarize(self):
        cdef uint64_t size = 0, unique_size = 0, chunks = 0, unique_chunks = 0
        cdef uint32_t *values
        cdef uint32_t refcount
        cdef unsigned char *key = NULL

        while True:
            key = hashindex_next_key(self.index, key)
            if not key:
                break
            unique_chunks += 1
            values = <uint32_t*> (key + self.key_size)
            refcount = _le32toh(values[0])
            assert refcount <= _MAX_VALUE, "invalid reference count"
            chunks += refcount
            unique_size += _le32toh(values[1])
            size += <uint64_t> _le32toh(values[1]) * _le32toh(values[0])

        return size, unique_size, unique_chunks, chunks

    def stats_against(self, ChunkIndex master_index):
        """
        Calculate chunk statistics of this index against *master_index*.

        A chunk is counted as unique if the number of references
        in this index matches the number of references in *master_index*.

        This index must be a subset of *master_index*.

        Return the same statistics tuple as summarize:
        size, unique_size, unique_chunks, chunks.
        """
        cdef uint64_t size = 0, unique_size = 0, chunks = 0, unique_chunks = 0
        cdef uint32_t our_refcount, chunk_size
        cdef const uint32_t *our_values
        cdef const uint32_t *master_values
        cdef const unsigned char *key = NULL
        cdef HashIndex *master = master_index.index

        while True:
            key = hashindex_next_key(self.index, key)
            if not key:
                break
            our_values = <const uint32_t*> (key + self.key_size)
            master_values = <const uint32_t*> hashindex_get(master, key)
            if not master_values:
                raise ValueError('stats_against: key contained in self but not in master_index.')
            our_refcount = _le32toh(our_values[0])
            chunk_size = _le32toh(master_values[1])

            chunks += our_refcount
            size += <uint64_t> chunk_size * our_refcount
            if our_values[0] == master_values[0]:
                # our refcount equals the master's refcount, so this chunk is unique to us
                unique_chunks += 1
                unique_size += chunk_size

        return size, unique_size, unique_chunks, chunks

    def add(self, key, refs, size):
        assert len(key) == self.key_size
        cdef uint32_t[2] data
        data[0] = _htole32(refs)
        data[1] = _htole32(size)
        self._add(<unsigned char*> key, data)

    cdef _add(self, unsigned char *key, uint32_t *data):
        cdef uint64_t refcount1, refcount2, result64
        values = <uint32_t*> hashindex_get(self.index, key)
        if values:
            refcount1 = _le32toh(values[0])
            refcount2 = _le32toh(data[0])
            assert refcount1 <= _MAX_VALUE, "invalid reference count"
            assert refcount2 <= _MAX_VALUE, "invalid reference count"
            result64 = refcount1 + refcount2
            values[0] = _htole32(min(result64, _MAX_VALUE))
            values[1] = data[1]
        else:
            if not hashindex_set(self.index, key, data):
                raise Exception('hashindex_set failed')

    def merge(self, ChunkIndex other):
        cdef unsigned char *key = NULL

        while True:
            key = hashindex_next_key(other.index, key)
            if not key:
                break
            self._add(key, <uint32_t*> (key + self.key_size))


cdef class ChunkKeyIterator:
    cdef ChunkIndex idx
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
        cdef uint32_t refcount = _le32toh(value[0])
        assert refcount <= _MAX_VALUE, "invalid reference count"
        return (<char *>self.key)[:self.key_size], ChunkIndexEntry(refcount, _le32toh(value[1]))


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


cdef class CacheSynchronizer:
    cdef ChunkIndex chunks
    cdef CacheSyncCtx *sync

    def __cinit__(self, chunks):
        self.chunks = chunks
        self.sync = cache_sync_init(self.chunks.index)
        if not self.sync:
            raise Exception('cache_sync_init failed')

    def __dealloc__(self):
        if self.sync:
            cache_sync_free(self.sync)

    def feed(self, chunk):
        cdef Py_buffer chunk_buf = ro_buffer(chunk)
        cdef int rc
        rc = cache_sync_feed(self.sync, chunk_buf.buf, chunk_buf.len)
        PyBuffer_Release(&chunk_buf)
        if not rc:
            error = cache_sync_error(self.sync)
            if error != NULL:
                raise ValueError('cache_sync_feed failed: ' + error.decode('ascii'))

    @property
    def num_files_totals(self):
        return cache_sync_num_files_totals(self.sync)

    @property
    def num_files_parts(self):
        return cache_sync_num_files_parts(self.sync)

    @property
    def size_totals(self):
        return cache_sync_size_totals(self.sync)

    @property
    def size_parts(self):
        return cache_sync_size_parts(self.sync)
