# -*- coding: utf-8 -*-
import os


cdef extern from "_hashindex.c":
    ctypedef struct HashIndex:
        pass

    HashIndex *hashindex_open(char *path, int readonly)
    HashIndex *hashindex_create(char *path, int capacity, int key_size, int value_size)
    int hashindex_get_size(HashIndex *index)
    int hashindex_clear(HashIndex *index)
    int hashindex_close(HashIndex *index)
    int hashindex_flush(HashIndex *index)
    void *hashindex_get(HashIndex *index, void *key)
    void *hashindex_next_key(HashIndex *index, void *key)
    int hashindex_delete(HashIndex *index, void *key)
    int hashindex_set(HashIndex *index, void *key, void *value)
    int _htole32(int v)
    int _le32toh(int v)


_NoDefault = object()

cdef class IndexBase:
    cdef HashIndex *index
    key_size = 32

    def __cinit__(self, path, readonly=False):
        self.index = hashindex_open(<bytes>os.fsencode(path), readonly)
        if not self.index:
            raise Exception('Failed to open %s' % path)

    def __dealloc__(self):
        if self.index:
            if not hashindex_close(self.index):
                raise Exception('hashindex_close failed')

    @classmethod
    def create(cls, path):
        index = hashindex_create(<bytes>os.fsencode(path), 0, cls.key_size, cls.value_size)
        if not index:
            raise Exception('Failed to create %s' % path)
        hashindex_close(index)
        return cls(path)

    def clear(self):
        if not hashindex_clear(self.index):
            raise Exception('hashindex_clear failed')

    def flush(self):
        if not hashindex_flush(self.index):
            raise Exception('hashindex_flush failed')

    def setdefault(self, key, value):
        if not key in self:
            self[key] = value

    def __delitem__(self, key):
        assert len(key) == 32
        if not hashindex_delete(self.index, <char *>key):
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
        return hashindex_get_size(self.index)


cdef class NSIndex(IndexBase):

    value_size = 8

    def __getitem__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        if not data:
            raise KeyError
        return _le32toh(data[0]), _le32toh(data[1])

    def __setitem__(self, key, value):
        assert len(key) == 32
        cdef int[2] data
        data[0] = _htole32(value[0])
        data[1] = _htole32(value[1])
        if not hashindex_set(self.index, <char *>key, data):
            raise Exception('hashindex_set failed')

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
        return self.key[:32], (_le32toh(value[0]), _le32toh(value[1]))


cdef class ChunkIndex(IndexBase):

    value_size = 12

    def __getitem__(self, key):
        assert len(key) == 32
        data = <int *>hashindex_get(self.index, <char *>key)
        if not data:
            raise KeyError
        return _le32toh(data[0]), _le32toh(data[1]), _le32toh(data[2])

    def __setitem__(self, key, value):
        assert len(key) == 32
        cdef int[3] data
        data[0] = _htole32(value[0])
        data[1] = _htole32(value[1])
        data[2] = _htole32(value[2])
        if not hashindex_set(self.index, <char *>key, data):
            raise Exception('hashindex_set failed')

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
        return self.key[:32], (_le32toh(value[0]), _le32toh(value[1]), _le32toh(value[2]))
