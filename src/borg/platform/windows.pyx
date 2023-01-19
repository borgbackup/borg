import os
import platform
from functools import lru_cache


cdef extern from 'windows.h':
    ctypedef void* HANDLE
    ctypedef int BOOL
    ctypedef unsigned long DWORD

    BOOL CloseHandle(HANDLE hObject)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dbProcessId)

    cdef extern int PROCESS_QUERY_INFORMATION


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    return "root"


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    if not user:
        # user is either None or the empty string
        return default
    return 0


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    return "root"


@lru_cache(maxsize=None)
def group2gid(group, default=None):
    if not group:
        # group is either None or the empty string
        return default
    return 0


def getosusername():
    """Return the os user name."""
    return os.getlogin()


def process_alive(host, pid, thread):
    """
    Check whether the (host, pid, thread_id) combination corresponds to a process potentially alive.
    """
    if host.split('@')[0].lower() != platform.node().lower():
        # Not running on the same node, assume running.
        return True

    # If the process can be opened, the process is alive.
    handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if handle != NULL:
        CloseHandle(handle)
        return True
    return False


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    raise NotImplementedError
