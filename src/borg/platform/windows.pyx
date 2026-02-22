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


def set_birthtime(path, birthtime_ns):
    """
    Set creation time (birthtime) on *path* to *birthtime_ns*.
    """
    import ctypes
    from ctypes import wintypes

    # Windows API Constants
    FILE_WRITE_ATTRIBUTES = 0x0100
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    # Convert ns to Windows FILETIME
    # Units: 100-nanosecond intervals
    # Epoch: Jan 1, 1601
    unix_epoch_in_100ns = 116444736000000000
    intervals = (birthtime_ns // 100) + unix_epoch_in_100ns

    ft = FILETIME()
    ft.dwLowDateTime = intervals & 0xFFFFFFFF
    ft.dwHighDateTime = intervals >> 32

    handle = ctypes.windll.kernel32.CreateFileW(
        str(path),
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if handle == -1:
        return

    try:
        # SetFileTime(handle, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
        ctypes.windll.kernel32.SetFileTime(handle, ctypes.byref(ft), None, None)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)
