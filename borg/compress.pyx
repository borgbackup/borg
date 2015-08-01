"""
A thin liblz4 wrapper for raw LZ4 compression / decompression.

Features:
    - lz4 is super fast
    - wrapper releases CPython's GIL to support multithreaded code
    - helper buffer only allocated once at instance creation and then reused

But beware:
    - this is not very generic, you MUST know the maximum uncompressed input
      data size you will feed into the compressor / get from the decompressor!
    - you must not do method calls to the same LZ4 instance from different
      threads at the same time - create one LZ4 instance per thread!
    - compress returns raw compressed data without adding any frame metadata
      (like checksums, magics, length of data, etc.)
    - decompress expects such raw compressed data as input
"""

from libc.stdlib cimport malloc, free


cdef extern from "lz4.h":
    int LZ4_compressBound(int inputSize)
    int LZ4_compress(const char* source, char* dest, int inputSize) nogil
    int LZ4_decompress_safe(const char* source, char* dest, int inputSize, int maxOutputSize) nogil


cdef class LZ4:
    cdef char *buffer  # helper buffer for (de)compression output
    cdef int bufsize  # size of this buffer
    cdef int max_isize  # maximum compressor input size safe for this bufsize

    def __cinit__(self, int max_isize):
        self.max_isize = max_isize
        # compute worst case bufsize for not compressible data:
        self.bufsize = LZ4_compressBound(max_isize)
        self.buffer = <char *>malloc(self.bufsize)
        if not self.buffer:
            raise MemoryError

    def __dealloc__(self):
        free(self.buffer)

    def compress(self, idata):
        cdef int isize = len(idata)
        if isize > self.max_isize:
            raise Exception('lz4 buffer might be too small, increase max_isize!')
        cdef int osize
        cdef char *source = idata
        cdef char *dest = self.buffer
        with nogil:
            osize = LZ4_compress(source, dest, isize)
        if not osize:
            raise Exception('lz4 compress failed')
        return dest[:osize]

    def decompress(self, idata):
        cdef int isize = len(idata)
        cdef int osize = self.bufsize
        cdef char *source = idata  # <-- does not work for memoryview idata, wants bytes
        cdef char *dest = self.buffer
        with nogil:
            osize = LZ4_decompress_safe(source, dest, isize, osize)
        if osize < 0:
            # malformed input data, buffer too small, ...
            raise Exception('lz4 decompress failed')
        return dest[:osize]
