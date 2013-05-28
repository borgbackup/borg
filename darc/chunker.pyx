# -*- coding: utf-8 -*-

from libc.stdlib cimport free

cdef extern from "_chunker.c":
    ctypedef int uint32_t
    ctypedef struct Chunker:
        pass
    Chunker *chunker_init(object fd, int window_size, int chunk_mask, int min_size, uint32_t seed)
    void chunker_free(Chunker *chunker)
    object chunker_process(Chunker *chunker)
    uint32_t *buzhash_init_table(uint32_t seed)
    uint32_t c_buzhash "buzhash"(const unsigned char *data, size_t len, const uint32_t *h)
    uint32_t c_buzhash_update  "buzhash_update"(uint32_t sum, unsigned char remove, unsigned char add, size_t len, const uint32_t *h)


cdef class chunkify:
    cdef Chunker *chunker

    def __cinit__(self, fd, window_size, chunk_mask, min_size, seed):
        self.chunker = chunker_init(fd, window_size, chunk_mask, min_size, seed & 0xffffffff)

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