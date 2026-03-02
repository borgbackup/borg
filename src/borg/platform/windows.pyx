import ctypes
from ctypes import wintypes
import msvcrt

import os
import platform


cdef extern from 'windows.h':
    ctypedef void* HANDLE
    ctypedef int BOOL
    ctypedef unsigned long DWORD

    BOOL CloseHandle(HANDLE hObject)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dbProcessId)

    cdef extern int PROCESS_QUERY_INFORMATION


# Windows API Constants
FILE_WRITE_ATTRIBUTES = 0x0100
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


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


def set_birthtime(path, birthtime_ns, *, fd=None):
    """
    Set creation time (birthtime) on *path* (or *fd*) to *birthtime_ns*.
    """
    # Convert ns to Windows FILETIME
    unix_epoch_in_100ns = 116444736000000000
    intervals = (birthtime_ns // 100) + unix_epoch_in_100ns

    ft = FILETIME()
    ft.dwLowDateTime = intervals & 0xFFFFFFFF
    ft.dwHighDateTime = intervals >> 32

    handle = -1
    if fd is not None:
        handle = msvcrt.get_osfhandle(fd)
        close_handle = False
    else:
        handle = ctypes.windll.kernel32.CreateFileW(
            str(path),
            FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        close_handle = True

    if handle == -1:
        return

    try:
        # SetFileTime(handle, lpCreationTime, lpLastAccessTime, lpLastWriteTime)
        ctypes.windll.kernel32.SetFileTime(handle, ctypes.byref(ft), None, None)
    finally:
        if close_handle:
            ctypes.windll.kernel32.CloseHandle(handle)


def set_timestamps(path, item, fd=None, follow_symlinks=False):
    """Set timestamps (mtime, atime, birthtime) from *item* on *path* (*fd*)."""
    # On Windows, we prefer using a single SetFileTime call if we have or can get a handle.
    handle = -1
    close_handle = False
    if fd is not None:
        handle = msvcrt.get_osfhandle(fd)
        close_handle = False
    elif path is not None:
        handle = ctypes.windll.kernel32.CreateFileW(
            str(path),
            FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        close_handle = True

    if handle != -1:
        try:
            mtime_ns = item.mtime
            mtime_intervals = (mtime_ns // 100) + 116444736000000000
            ft_mtime = FILETIME(mtime_intervals & 0xFFFFFFFF, mtime_intervals >> 32)

            atime_ns = item.atime if "atime" in item else mtime_ns
            atime_intervals = (atime_ns // 100) + 116444736000000000
            ft_atime = FILETIME(atime_intervals & 0xFFFFFFFF, atime_intervals >> 32)

            ft_birthtime = None
            if "birthtime" in item:
                birthtime_ns = item.birthtime
                birthtime_intervals = (birthtime_ns // 100) + 116444736000000000
                ft_birthtime = FILETIME(birthtime_intervals & 0xFFFFFFFF, birthtime_intervals >> 32)

            ctypes.windll.kernel32.SetFileTime(
                handle,
                ctypes.byref(ft_birthtime) if ft_birthtime else None,
                ctypes.byref(ft_atime),
                ctypes.byref(ft_mtime),
            )
            return
        finally:
            if close_handle:
                ctypes.windll.kernel32.CloseHandle(handle)

    # Fallback to os.utime if handle acquisition failed or wasn't attempted (path only)
    # Note: os.utime on Windows doesn't support birthtime or fd.
    mtime = item.mtime
    atime = item.atime if "atime" in item else mtime
    try:
        os.utime(path, ns=(atime, mtime))
    except OSError:
        pass
