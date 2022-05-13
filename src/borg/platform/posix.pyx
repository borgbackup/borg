import errno
import os
import grp
import pwd
from functools import lru_cache

from libc.errno cimport errno as c_errno

from cpython.mem cimport PyMem_Free
from libc.stddef cimport wchar_t

cdef extern from "wchar.h":
    # https://www.man7.org/linux/man-pages/man3/wcswidth.3.html
    cdef int wcswidth(const wchar_t *s, size_t n)


cdef extern from "Python.h":
    # https://docs.python.org/3/c-api/unicode.html#c.PyUnicode_AsWideCharString
    wchar_t* PyUnicode_AsWideCharString(object, Py_ssize_t*) except NULL


def get_errno():
    return c_errno


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


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def group2gid(group, default=None):
    try:
        return group and grp.getgrnam(group).gr_gid
    except KeyError:
        return default


def posix_acl_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid
    """
    from ..helpers import safe_decode, safe_encode
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if len(fields) == 4:
                entries.append(':'.join([fields[0], fields[3], fields[2]]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def getosusername():
    """Return the os user name."""
    uid = os.getuid()
    return uid2user(uid, uid)
