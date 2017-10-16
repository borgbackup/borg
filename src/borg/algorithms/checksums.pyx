from ..helpers import bin_to_hex

from libc.stdint cimport uint32_t
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release
from cpython.bytes cimport PyBytes_FromStringAndSize


cdef extern from "crc32_dispatch.c":
    uint32_t _crc32_slice_by_8 "crc32_slice_by_8"(const void* data, size_t length, uint32_t initial_crc)
    uint32_t _crc32_clmul "crc32_clmul"(const void* data, size_t length, uint32_t initial_crc)

    int _have_clmul "have_clmul"()


cdef extern from "xxh64/xxhash.c":
    ctypedef struct XXH64_canonical_t:
        char digest[8]

    ctypedef struct XXH64_state_t:
        pass  # opaque

    ctypedef unsigned long long XXH64_hash_t

    ctypedef enum XXH_errorcode:
        XXH_OK,
        XXH_ERROR

    XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed);

    XXH_errorcode XXH64_reset(XXH64_state_t* statePtr, unsigned long long seed);
    XXH_errorcode XXH64_update(XXH64_state_t* statePtr, const void* input, size_t length);
    XXH64_hash_t XXH64_digest(const XXH64_state_t* statePtr);

    void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash);
    XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src);


cdef Py_buffer ro_buffer(object data) except *:
    cdef Py_buffer view
    PyObject_GetBuffer(data, &view, PyBUF_SIMPLE)
    return view


def crc32_slice_by_8(data, value=0):
    cdef Py_buffer data_buf = ro_buffer(data)
    cdef uint32_t val = value
    try:
        return _crc32_slice_by_8(data_buf.buf, data_buf.len, val)
    finally:
        PyBuffer_Release(&data_buf)


def crc32_clmul(data, value=0):
    cdef Py_buffer data_buf = ro_buffer(data)
    cdef uint32_t val = value
    try:
        return _crc32_clmul(data_buf.buf, data_buf.len, val)
    finally:
        PyBuffer_Release(&data_buf)


have_clmul = _have_clmul()
if have_clmul:
    crc32 = crc32_clmul
else:
    crc32 = crc32_slice_by_8


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
    cdef XXH64_state_t state

    def __cinit__(self, seed=0):
        cdef unsigned long long _seed = seed
        if XXH64_reset(&self.state, _seed) != XXH_OK:
            raise Exception('XXH64_reset failed')

    def update(self, data):
        cdef Py_buffer data_buf = ro_buffer(data)
        try:
            if XXH64_update(&self.state, data_buf.buf, data_buf.len) != XXH_OK:
                raise Exception('XXH64_update failed')
        finally:
            PyBuffer_Release(&data_buf)

    def digest(self):
        cdef XXH64_hash_t hash
        cdef XXH64_canonical_t digest
        hash = XXH64_digest(&self.state)
        XXH64_canonicalFromHash(&digest, hash)
        return PyBytes_FromStringAndSize(<const char*> digest.digest, 8)

    def hexdigest(self):
        return bin_to_hex(self.digest())
