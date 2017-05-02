
from libc.stdint cimport uint32_t
from cpython.buffer cimport PyBUF_SIMPLE, PyObject_GetBuffer, PyBuffer_Release


cdef extern from "crc32_dispatch.c":
    uint32_t _crc32_slice_by_8 "crc32_slice_by_8"(const void* data, size_t length, uint32_t initial_crc)
    uint32_t _crc32_clmul "crc32_clmul"(const void* data, size_t length, uint32_t initial_crc)

    int _have_clmul "have_clmul"()


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
