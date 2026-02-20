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
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_WRITE_THROUGH = 0x80000000
ERROR_FILE_EXISTS = 80

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
            GENERIC_WRITE,
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
            mode = "wb" if binary else "w"
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
