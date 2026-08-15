import ctypes
import ctypes.wintypes
import errno as errno_mod
import msvcrt
import os
import platform

from .base import SyncFile as BaseSyncFile


cdef extern from 'windows.h':
    ctypedef void* HANDLE
    ctypedef int BOOL
    ctypedef unsigned long DWORD

    BOOL CloseHandle(HANDLE hObject)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dbProcessId)

    cdef extern int PROCESS_QUERY_INFORMATION


# Win32 API constants for CreateFileW
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_WRITE_THROUGH = 0x80000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
ERROR_FILE_EXISTS = 80

# a FILETIME counts 100ns intervals since 1601-01-01, our timestamps count ns since 1970-01-01.
FILETIME_EPOCH_OFFSET_NS = 11644473600 * 1000000000
# SetFileTime gives a special meaning to 0 ("do not change") and to all bits set
# ("do not update this timestamp for this handle any more"), so avoid these values.
FILETIME_MIN, FILETIME_MAX = 1, 0xFFFFFFFFFFFFFFFE

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_CreateFileW = _kernel32.CreateFileW
_CreateFileW.restype = ctypes.wintypes.HANDLE
_CreateFileW.argtypes = [
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.HANDLE,
]
_CloseHandle = _kernel32.CloseHandle
_SetFileTime = _kernel32.SetFileTime
_SetFileTime.restype = ctypes.wintypes.BOOL
_SetFileTime.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.FILETIME),
    ctypes.POINTER(ctypes.wintypes.FILETIME),
    ctypes.POINTER(ctypes.wintypes.FILETIME),
]
INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value


class SyncFile(BaseSyncFile):
    """
    Windows SyncFile using FILE_FLAG_WRITE_THROUGH for data durability.

    FILE_FLAG_WRITE_THROUGH instructs Windows to write through any intermediate
    cache and go directly to disk, providing data durability guarantees similar
    to fdatasync/F_FULLFSYNC on POSIX/macOS systems.

    When an already-open fd is provided, falls back to base implementation.
    """

    def __init__(self, path, *, fd=None, binary=False):
        if fd is not None:
            # An already-opened fd was provided (e.g., from SaveFile via mkstemp).
            # We cannot change its flags, so fall back to the base implementation.
            super().__init__(path, fd=fd, binary=binary)
            return

        self.path = path
        handle = _CreateFileW(
            str(path),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            None,
            CREATE_NEW,  # fail if file exists, matching Python's 'x' mode
            FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if error == ERROR_FILE_EXISTS:
                raise FileExistsError(errno_mod.EEXIST, os.strerror(errno_mod.EEXIST), str(path))
            raise ctypes.WinError(error)

        try:
            oflags = os.O_BINARY if binary else os.O_TEXT
            c_fd = msvcrt.open_osfhandle(handle, oflags)
        except Exception:
            _CloseHandle(handle)
            raise

        try:
            mode = "r+b" if binary else "r+"
            self.f = os.fdopen(c_fd, mode=mode)
        except Exception:
            os.close(c_fd)  # Also closes the underlying Windows handle
            raise
        self.fd = self.f.fileno()

    def sync(self):
        """Flush and sync to persistent storage.

        With FILE_FLAG_WRITE_THROUGH, writes already go to stable storage.
        We still call os.fsync (FlushFileBuffers) for belt-and-suspenders safety.
        """
        self.f.flush()
        os.fsync(self.fd)


def _ns_to_filetime(ns):
    """Convert a timestamp in ns since 1970-01-01 to a Win32 FILETIME."""
    ft = (ns + FILETIME_EPOCH_OFFSET_NS) // 100
    # clamp to what a FILETIME can express (borg timestamps have a much wider range).
    ft = min(max(ft, FILETIME_MIN), FILETIME_MAX)
    return ctypes.wintypes.FILETIME(ft & 0xFFFFFFFF, ft >> 32)


def set_times(path, *, atime_ns, mtime_ns, birthtime_ns=None, fd=None, follow_symlinks=True):
    """
    Set the timestamps of *path* (or of the open file descriptor *fd*, if given).

    Uses SetFileTime rather than os.utime, because os.utime on Windows can neither work on
    a file descriptor nor on a symlink itself, nor can it set the birthtime (creation time).

    Raises OSError if the timestamps could not be set.
    """
    if fd is not None:
        handle, close_handle = msvcrt.get_osfhandle(fd), False
    else:
        # FILE_FLAG_BACKUP_SEMANTICS is required to get a handle for a directory.
        flags = FILE_FLAG_BACKUP_SEMANTICS
        if not follow_symlinks:
            flags |= FILE_FLAG_OPEN_REPARSE_POINT
        handle = _CreateFileW(
            str(path),
            FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        close_handle = True
    try:
        atime = _ns_to_filetime(atime_ns)
        mtime = _ns_to_filetime(mtime_ns)
        birthtime = _ns_to_filetime(birthtime_ns) if birthtime_ns is not None else None
        if not _SetFileTime(
            handle, ctypes.byref(birthtime) if birthtime is not None else None, ctypes.byref(atime), ctypes.byref(mtime)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if close_handle:
            _CloseHandle(handle)


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
