cdef extern from "wchar.h":
    cdef int wcswidth(const Py_UNICODE *str, size_t n)
 
def swidth(s):
    str_len = len(s)
    terminal_width = wcswidth(s, str_len)
    if terminal_width >= 0:
        return terminal_width
    else:
        return str_len
