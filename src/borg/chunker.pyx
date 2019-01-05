# -*- coding: utf-8 -*-

API_VERSION = '1.1_02'

from libc.stdlib cimport free

cdef extern from "_chunker.c":
    ctypedef int uint32_t
    ctypedef struct _Chunker "Chunker":
        pass
    _Chunker *chunker_init(int window_size, int chunk_mask, int min_size, int max_size, uint32_t seed)
    void chunker_set_fd(_Chunker *chunker, object f, int fd)
    void chunker_free(_Chunker *chunker)
    object chunker_process(_Chunker *chunker)
    uint32_t *buzhash_init_table(uint32_t seed)
    uint32_t c_buzhash "buzhash"(unsigned char *data, size_t len, uint32_t *h)
    uint32_t c_buzhash_update  "buzhash_update"(uint32_t sum, unsigned char remove, unsigned char add, size_t len, uint32_t *h)


cdef class Chunker:
    """
    Content-Defined Chunker, variable chunk sizes.

    This chunker does quite some effort to mostly cut the same-content chunks, even if
    the content moves to a different offset inside the file. It uses the buzhash
    rolling-hash algorithm to identify the chunk cutting places by looking at the
    content inside the moving window and computing the rolling hash value over the
    window contents. If the last n bits of the rolling hash are 0, a chunk is cut.
    Additionally it obeys some more criteria, like a minimum and maximum chunk size.
    It also uses a per-repo random seed to avoid some chunk length fingerprinting attacks.
    """
    cdef _Chunker *chunker

    def __cinit__(self, int seed, int chunk_min_exp, int chunk_max_exp, int hash_mask_bits, int hash_window_size):
        min_size = 1 << chunk_min_exp
        max_size = 1 << chunk_max_exp
        # see chunker_process, first while loop condition, first term must be able to get True:
        assert hash_window_size + min_size + 1 <= max_size, "too small max_size"
        hash_mask = (1 << hash_mask_bits) - 1
        self.chunker = chunker_init(hash_window_size, hash_mask, min_size, max_size, seed & 0xffffffff)

    def chunkify(self, fd, fh=-1):
        """
        Cut a file into chunks.

        :param fd: Python file object
        :param fh: OS-level file handle (if available),
                   defaults to -1 which means not to use OS-level fd.
        """
        chunker_set_fd(self.chunker, fd, fh)
        return self

    def __dealloc__(self):
        if self.chunker:
            chunker_free(self.chunker)

    def __iter__(self):
        return self

    def __next__(self):
        return chunker_process(self.chunker)


def get_chunker(algo, *params, **kw):
    if algo == 'buzhash':
        seed = kw['seed']
        return Chunker(seed, *params)
    raise TypeError('unsupported chunker algo %r' % algo)


def max_chunk_size(algo, *params):
    # see also parseformat.ChunkerParams return values
    if algo == 'buzhash':
        return 1 << params[1]
    raise TypeError('unsupported chunker algo %r' % algo)


def buzhash(data, unsigned long seed):
    cdef uint32_t *table
    cdef uint32_t sum
    table = buzhash_init_table(seed & 0xffffffff)
    sum = c_buzhash(<const unsigned char *> data, len(data), table)
    free(table)
    return sum


def buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, unsigned long seed):
    cdef uint32_t *table
    table = buzhash_init_table(seed & 0xffffffff)
    sum = c_buzhash_update(sum, remove, add, len, table)
    free(table)
    return sum
