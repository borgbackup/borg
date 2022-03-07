# cython: language_level=3

import errno
import os


from cpython.mem cimport PyMem_Free
from libc.stddef cimport wchar_t

cdef extern from "wchar.h":
    # https://www.man7.org/linux/man-pages/man3/wcswidth.3.html
    cdef int wcswidth(const wchar_t *s, size_t n)


cdef extern from "Python.h":
    # https://docs.python.org/3/c-api/unicode.html#c.PyUnicode_AsWideCharString
    wchar_t* PyUnicode_AsWideCharString(object, Py_ssize_t*) except NULL


def swidth(s):
    cdef Py_ssize_t size
    cdef wchar_t *as_wchar = PyUnicode_AsWideCharString(s, &size)
    terminal_width = wcswidth(as_wchar, <size_t>size)
    PyMem_Free(as_wchar)
    if terminal_width >= 0:
        return terminal_width
    else:
        return len(s)


def process_alive(host, pid, thread):
    """
    Check if the (host, pid, thread_id) combination corresponds to a potentially alive process.

    If the process is local, then this will be accurate. If the process is not local, then this
    returns always True, since there is no real way to check.
    """
    from . import local_pid_alive
    from . import hostid

    assert isinstance(host, str)
    assert isinstance(hostid, str)
    assert isinstance(pid, int)
    assert isinstance(thread, int)

    if host != hostid:
        return True

    if thread != 0:
        # Currently thread is always 0, if we ever decide to set this to a non-zero value,
        # this code needs to be revisited, too, to do a sensible thing
        return True

    return local_pid_alive(pid)


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    try:
        # This doesn't work on Windows.
        # This does not kill anything, 0 means "see if we can send a signal to this process or not".
        # Possible errors: No such process (== stale lock) or permission denied (not a stale lock).
        # If the exception is not raised that means such a pid is valid and we can send a signal to it.
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH = no such process
            return False
        # Any other error (eg. permissions) means that the process ID refers to a live process.
        return True
