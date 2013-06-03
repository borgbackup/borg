# -*- coding: utf-8 -*-

cdef extern from "_hashindex.c":
    ctypedef struct HashIndex:
        pass

    HashIndex *hashindex_open(char *path)
    HashIndex *hashindex_create(char *path, int capacity, int key_size, int value_size)
    int hashindex_get_size(HashIndex *index)
    void hashindex_clear(HashIndex *index)
    void hashindex_close(HashIndex *index)
    void hashindex_flush(HashIndex *index)
    void *hashindex_get(HashIndex *index, void *key)
    void *hashindex_next_key(HashIndex *index, void *key)
    void hashindex_delete(HashIndex *index, void *key)
    void hashindex_set(HashIndex *index, void *key, void *value)


_NoDefault = object()

cdef class IndexBase:
    cdef HashIndex *index

    def __cinit__(self, path):
        self.index = hashindex_open(path)
        if not self.index:
            raise Exception('Failed to open %s' % path)

    def __dealloc__(self):
        if self.index:
            hashindex_close(self.index)

    def clear(self):
        hashindex_clear(self.index)

    def flush(self):
        hashindex_flush(self.index)

    def setdefault(self, key, value):
        if not key in self:
            self[key] = value

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
        return hashindex_get_size(self.index)


cdef class NSIndex(IndexBase):

    @classmethod
    def create(cls, path, capacity=16):
        index = hashindex_create(path, capacity, 32, 8)
        hashindex_close(index)
        return cls(path)

    def __getitem__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        if not data:
            raise KeyError
        return data[0], data[1]

    def __delitem__(self, key):
        assert len(key) == 32
        hashindex_delete(self.index, <char *>key)

    def __setitem__(self, key, value):
        assert len(key) == 32
        cdef int[2] data
        data[0] = value[0]
        data[1] = value[1]
        hashindex_set(self.index, <char *>key, data)

    def __contains__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        return data != NULL

    def iteritems(self, marker=None, limit=0):
        iter = NSKeyIterator()
        iter.index = self.index
        return iter


cdef class NSKeyIterator:
    cdef HashIndex *index
    cdef char *key

    def __cinit__(self):
        self.key = NULL

    def __iter__(self):
        return self

    def __next__(self):
        self.key = <char *>hashindex_next_key(self.index, <char *>self.key)
        if not self.key:
            raise StopIteration
        cdef int *value = <int *>(self.key + 32)
        return self.key[:32], (value[0], value[1])


cdef class ChunkIndex(IndexBase):

    @classmethod
    def create(cls, path, capacity=16):
        index = hashindex_create(path, capacity, 32, 12)
        hashindex_close(index)
        return cls(path)

    def __getitem__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        if not data:
            raise KeyError
        return data[0], data[1], data[2]

    def __delitem__(self, key):
        assert len(key) == 32
        hashindex_delete(self.index, <char *>key)

    def __setitem__(self, key, value):
        assert len(key) == 32
        cdef int[3] data
        data[0] = value[0]
        data[1] = value[1]
        data[2] = value[2]
        hashindex_set(self.index, <char *>key, data)

    def __contains__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        return data != NULL

    def iteritems(self, marker=None, limit=0):
        iter = ChunkKeyIterator()
        iter.index = self.index
        return iter


cdef class ChunkKeyIterator:
    cdef HashIndex *index
    cdef char *key

    def __cinit__(self):
        self.key = NULL

    def __iter__(self):
        return self

    def __next__(self):
        self.key = <char *>hashindex_next_key(self.index, <char *>self.key)
        if not self.key:
            raise StopIteration
        cdef int *value = <int *>(self.key + 32)
        return self.key[:32], (value[0], value[1], value[2])


cdef class BandIndex(IndexBase):

    @classmethod
    def create(cls, path, capacity=16):
        index = hashindex_create(path, capacity, 4, 4)
        hashindex_close(index)
        return cls(path)

    def __getitem__(self, key):
        cdef int k = key
        data = <int *>hashindex_get(self.index, &k)
        if not data:
            raise KeyError
        return data[0]

    def __delitem__(self, key):
        cdef int k = key
        hashindex_delete(self.index, &k)

    def __setitem__(self, key, value):
        cdef int k = key
        cdef int v = value
        hashindex_set(self.index, &k, &v)

    def __contains__(self, key):
        cdef int k = key
        data = <int *>hashindex_get(self.index, &k)
        return data != NULL

    def iteritems(self, marker=None, limit=0):
        iter = BandKeyIterator()
        iter.index = self.index
        return iter


cdef class BandKeyIterator:
    cdef HashIndex *index
    cdef int *key

    def __cinit__(self):
        self.key = NULL

    def __iter__(self):
        return self

    def __next__(self):
        self.key = <int *>hashindex_next_key(self.index, <char *>self.key)
        if not self.key:
            raise StopIteration
        return self.key[0], self.key[1]
