import zlib

from .platformflags import is_darwin
from .helpers import bin_to_hex

from libc.stdint cimport uint32_t
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize


cdef extern from "xxhash.h":
    ctypedef struct XXH64_canonical_t:
        char digest[8]

    ctypedef struct XXH64_state_t:
        pass  # opaque

    ctypedef unsigned long long XXH64_hash_t

    ctypedef enum XXH_errorcode:
        XXH_OK,
        XXH_ERROR

    XXH64_state_t* XXH64_createState()
    XXH_errorcode XXH64_freeState(XXH64_state_t* statePtr)
    XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed)

    XXH_errorcode XXH64_reset(XXH64_state_t* statePtr, unsigned long long seed)
    XXH_errorcode XXH64_update(XXH64_state_t* statePtr, const void* input, size_t length)
    XXH64_hash_t XXH64_digest(const XXH64_state_t* statePtr)

    void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash)
    XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src)


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


# Borg 2.0 repositories do not compute CRC32 over large amounts of data,
# so speed does not matter much anymore, and we can just use zlib.crc32.
crc32 = zlib.crc32


def xxh64(data, seed=0):
    cdef unsigned long long _seed = seed
    cdef XXH64_hash_t hash
    cdef XXH64_canonical_t digest
    cdef Py_buffer data_buf = ro_buffer(data)
    try:
        hash = XXH64(data_buf.buf, data_buf.len, _seed)
    finally:
        PyBuffer_Release(&data_buf)
    XXH64_canonicalFromHash(&digest, hash)
    return PyBytes_FromStringAndSize(<const char*> digest.digest, 8)


cdef class StreamingXXH64:
    cdef XXH64_state_t* state

    def __cinit__(self, seed=0):
        self.state = XXH64_createState()
        cdef unsigned long long _seed = seed
        if XXH64_reset(self.state, _seed) != XXH_OK:
            raise Exception('XXH64_reset failed')

    def __dealloc__(self):
        XXH64_freeState(self.state)

    def update(self, data):
        cdef Py_buffer data_buf = ro_buffer(data)
        try:
            if XXH64_update(self.state, data_buf.buf, data_buf.len) != XXH_OK:
                raise Exception('XXH64_update failed')
        finally:
            PyBuffer_Release(&data_buf)

    def digest(self):
        cdef XXH64_hash_t hash
        cdef XXH64_canonical_t digest
        hash = XXH64_digest(self.state)
        XXH64_canonicalFromHash(&digest, hash)
        return PyBytes_FromStringAndSize(<const char*> digest.digest, 8)

    def hexdigest(self):
        return bin_to_hex(self.digest())
