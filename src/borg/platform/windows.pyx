import os
import platform


cdef extern from 'windows.h':
    ctypedef void* HANDLE
    ctypedef int BOOL
    ctypedef unsigned long DWORD

    BOOL CloseHandle(HANDLE hObject)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dbProcessId)

    cdef extern int PROCESS_QUERY_INFORMATION


def getosusername():
    """Return the OS username."""
    return os.getlogin()


def process_alive(host, pid, thread):
    """
    Check whether the (host, pid, thread_id) combination corresponds to a process potentially alive.
    """
    if host.split('@')[0].lower() != platform.node().lower():
        # If not running on the same node, assume the process is running.
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
