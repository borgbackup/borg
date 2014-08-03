# -*- coding: utf-8 -*-

API_VERSION = 2

from libc.stdlib cimport free

cdef extern from "_chunker.c":
    ctypedef int uint32_t
    ctypedef struct _Chunker "Chunker":
        pass
    _Chunker *chunker_init(int window_size, int chunk_mask, int min_size, uint32_t seed)
    void chunker_set_fd(_Chunker *chunker, object fd)
    void chunker_free(_Chunker *chunker)
    object chunker_process(_Chunker *chunker)
    uint32_t *buzhash_init_table(uint32_t seed)
    uint32_t c_buzhash "buzhash"(unsigned char *data, size_t len, uint32_t *h)
    uint32_t c_buzhash_update  "buzhash_update"(uint32_t sum, unsigned char remove, unsigned char add, size_t len, uint32_t *h)


cdef class Chunker:
    cdef _Chunker *chunker

    def __cinit__(self, window_size, chunk_mask, min_size, seed):
        self.chunker = chunker_init(window_size, chunk_mask, min_size, seed & 0xffffffff)

    def chunkify(self, fd):
        chunker_set_fd(self.chunker, fd)
        return self

    def __dealloc__(self):
        if self.chunker:
            chunker_free(self.chunker)

    def __iter__(self):
        return self

    def __next__(self):
        return chunker_process(self.chunker)


def buzhash(unsigned char *data, unsigned long seed):
    cdef uint32_t *table
    cdef uint32_t sum
    table = buzhash_init_table(seed & 0xffffffff)
    sum = c_buzhash(data, len(data), table)
    free(table)
    return sum


def buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, unsigned long seed):
    cdef uint32_t *table
    table = buzhash_init_table(seed & 0xffffffff)
    sum = c_buzhash_update(sum, remove, add, len, table)
    free(table)
    return sum