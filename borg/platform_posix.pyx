cdef extern from "wchar.h":
    cdef int wcswidth(const Py_UNICODE *str, size_t n)
 
def swidth(s):
    return wcswidth(s, len(s))
