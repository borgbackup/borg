API_VERSION = '1.2_01'

import errno
import os
from collections import namedtuple

from .constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros

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


# this will be True if Python's seek implementation supports data/holes seeking.
# this does not imply that it will actually work on the filesystem,
# because the FS also needs to support this.
has_seek_hole = hasattr(os, 'SEEK_DATA') and hasattr(os, 'SEEK_HOLE')


_Chunk = namedtuple('_Chunk', 'meta data')
_Chunk.__doc__ = """\
    Chunk namedtuple

    meta is always a dictionary, data depends on allocation.

    data chunk read from a DATA range of a file (not from a sparse hole):
        meta = {'allocation' = CH_DATA, 'size' = size_of_chunk }
        data = read_data [bytes or memoryview]

    all-zero chunk read from a DATA range of a file (not from a sparse hole, but detected to be all-zero):
        meta = {'allocation' = CH_ALLOC, 'size' = size_of_chunk }
        data = None

    all-zero chunk from a HOLE range of a file (from a sparse hole):
        meta = {'allocation' = CH_HOLE, 'size' = size_of_chunk }
        data = None
"""

def Chunk(data, **meta):
    return _Chunk(meta, data)


def dread(offset, size, fd=None, fh=-1):
    use_fh = fh >= 0
    if use_fh:
        data = os.read(fh, size)
        if hasattr(os, 'posix_fadvise'):
            # UNIX only and, in case of block sizes that are not a multiple of the
            # system's page size, better be used with a bug fixed linux kernel > 4.6.0,
            # see comment/workaround in _chunker.c and borgbackup issue #907.
            os.posix_fadvise(fh, offset, len(data), os.POSIX_FADV_DONTNEED)
        return data
    else:
        return fd.read(size)


def dseek(amount, whence, fd=None, fh=-1):
    use_fh = fh >= 0
    if use_fh:
        return os.lseek(fh, amount, whence)
    else:
        return fd.seek(amount, whence)


def dpos_curr_end(fd=None, fh=-1):
    """
    determine current position, file end position (== file length)
    """
    curr = dseek(0, os.SEEK_CUR, fd, fh)
    end = dseek(0, os.SEEK_END, fd, fh)
    dseek(curr, os.SEEK_SET, fd, fh)
    return curr, end


def sparsemap(fd=None, fh=-1):
    """
    generator yielding a (start, length, is_data) tuple for each range.
    is_data is indicating data ranges (True) or hole ranges (False).

    note:
    the map is generated starting from the current seek position (it
    is not required to be 0 / to be at the start of the file) and
    work from there up to the end of the file.
    when the generator is finished, the file pointer position will be
    reset to where it was before calling this function.
    """
    curr, file_len = dpos_curr_end(fd, fh)
    start = curr
    try:
        whence = os.SEEK_HOLE
        while True:
            is_data = whence == os.SEEK_HOLE  # True: range with data, False: range is a hole
            try:
                end = dseek(start, whence, fd, fh)
            except OSError as e:
                if e.errno == errno.ENXIO:
                    if not is_data and start < file_len:
                        # if there is a hole at the end of a file, we can not find the file end by SEEK_DATA
                        # (because we run into ENXIO), thus we must manually deal with this case:
                        end = file_len
                        yield (start, end - start, is_data)
                    break
                else:
                    raise
            # we do not want to yield zero-length ranges with start == end:
            if end > start:
                yield (start, end - start, is_data)
            start = end
            whence = os.SEEK_DATA if is_data else os.SEEK_HOLE
    finally:
        # seek to same position as before calling this function
        dseek(curr, os.SEEK_SET, fd, fh)


class ChunkerFixed:
    """
    This is a simple chunker for input data with data usually staying at same
    offset and / or with known block/record sizes:

    - raw disk images
    - block devices
    - database files with simple header + fixed-size records layout

    It optionally supports:

    - a header block of different size
    - using a sparsemap to only read data ranges and seek over hole ranges
      for sparse files.
    - using an externally given filemap to only read specific ranges from
      a file.

    Note: the last block of a data or hole range may be less than the block size,
          this is supported and not considered to be an error.
    """
    def __init__(self, block_size, header_size=0, sparse=False):
        self.block_size = block_size
        self.header_size = header_size
        # should borg try to do sparse input processing?
        # whether it actually can be done depends on the input file being seekable.
        self.try_sparse = sparse and has_seek_hole
        assert block_size <= len(zeros)

    def chunkify(self, fd=None, fh=-1, fmap=None):
        """
        Cut a file into chunks.

        :param fd: Python file object
        :param fh: OS-level file handle (if available),
                   defaults to -1 which means not to use OS-level fd.
        :param fmap: a file map, same format as generated by sparsemap
        """
        if fmap is None:
            if self.try_sparse:
                try:
                    if self.header_size > 0:
                        header_map = [(0, self.header_size, True), ]
                        dseek(self.header_size, os.SEEK_SET, fd, fh)
                        body_map = list(sparsemap(fd, fh))
                        dseek(0, os.SEEK_SET, fd, fh)
                    else:
                        header_map = []
                        body_map = list(sparsemap(fd, fh))
                except OSError as err:
                    # seeking did not work
                    pass
                else:
                    fmap = header_map + body_map

            if fmap is None:
                # either sparse processing (building the fmap) was not tried or it failed.
                # in these cases, we just build a "fake fmap" that considers the whole file
                # as range(s) of data (no holes), so we can use the same code.
                # we build different fmaps here for the purpose of correct block alignment
                # with or without a header block (of potentially different size).
                if self.header_size > 0:
                    header_map = [(0, self.header_size, True), ]
                    body_map = [(self.header_size, 2 ** 62, True), ]
                else:
                    header_map = []
                    body_map = [(0, 2 ** 62, True), ]
                fmap = header_map + body_map

        offset = 0
        for range_start, range_size, is_data in fmap:
            if range_start != offset:
                # this is for the case when the fmap does not cover the file completely,
                # e.g. it could be without the ranges of holes or of unchanged data.
                offset = range_start
                dseek(offset, os.SEEK_SET, fd, fh)
            while range_size:
                wanted = min(range_size, self.block_size)
                if is_data:
                    # read block from the range
                    data = dread(offset, wanted, fd, fh)
                    got = len(data)
                    if zeros.startswith(data):
                        data = None
                        allocation = CH_ALLOC
                    else:
                        allocation = CH_DATA
                else:  # hole
                    # seek over block from the range
                    pos = dseek(wanted, os.SEEK_CUR, fd, fh)
                    got = pos - offset
                    data = None
                    allocation = CH_HOLE
                if got > 0:
                    offset += got
                    range_size -= got
                    yield Chunk(data, size=got, allocation=allocation)
                if got < wanted:
                    # we did not get enough data, looks like EOF.
                    return


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
        assert max_size <= len(zeros)
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
        data = chunker_process(self.chunker)
        got = len(data)
        # we do not have SEEK_DATA/SEEK_HOLE support in chunker_process C code,
        # but we can just check if data was all-zero (and either came from a hole
        # or from stored zeros - we can not detect that here).
        if zeros.startswith(data):
            data = None
            allocation = CH_ALLOC
        else:
            allocation = CH_DATA
        return Chunk(data, size=got, allocation=allocation)


def get_chunker(algo, *params, **kw):
    if algo == 'buzhash':
        seed = kw['seed']
        return Chunker(seed, *params)
    if algo == 'fixed':
        sparse = kw['sparse']
        return ChunkerFixed(*params, sparse=sparse)
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
