import errno
import os
import socket
import uuid

from ..helpers import safe_unlink
from ..platformflags import is_win32

"""
platform base module
====================

Contains platform API implementations based on what Python itself provides. More specific
APIs are stubs in this module.

When functions in this module use platform APIs themselves they access the public
platform API: that way platform APIs provided by the platform-specific support module
are correctly composed into the base functionality.
"""

API_VERSION = "1.2_05"

fdatasync = getattr(os, "fdatasync", os.fsync)

from .xattr import ENOATTR


def listxattr(path, *, follow_symlinks=False):
    """
    Return xattr names of a file (list of bytes objects).

    *path* can either be a path (bytes) or an open file descriptor (int).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.
    """
    return []


def getxattr(path, name, *, follow_symlinks=False):
    """
    Read xattr and return its value (as bytes).

    *path* can either be a path (bytes) or an open file descriptor (int).
    *name* is the name of the xattr to read (bytes).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.
    """
    # as this base dummy implementation returns [] from listxattr,
    # it must raise here for any given name:
    raise OSError(ENOATTR, os.strerror(ENOATTR), path)


def setxattr(path, name, value, *, follow_symlinks=False):
    """
    Write xattr on *path*.

    *path* can either be a path (bytes) or an open file descriptor (int).
    *name* is the name of the xattr to read (bytes).
    *value* is the value to write (bytes).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.
    """


def acl_get(path, item, st, numeric_ids=False, fd=None):
    """
    Saves ACL Entries

    If `numeric_ids` is True the user/group field is not preserved only uid/gid
    """


def acl_set(path, item, numeric_ids=False, fd=None):
    """
    Restore ACL Entries

    If `numeric_ids` is True the stored uid/gid is used instead
    of the user/group names
    """


try:
    from os import lchflags  # type: ignore[attr-defined]

    def set_flags(path, bsd_flags, fd=None):
        lchflags(path, bsd_flags)

except ImportError:

    def set_flags(path, bsd_flags, fd=None):
        pass


def get_flags(path, st, fd=None):
    """Return BSD-style file flags for path or stat without following symlinks."""
    return getattr(st, "st_flags", 0)


def sync_dir(path):
    if is_win32:
        # Opening directories is not supported on windows.
        # TODO: do we need to handle this in some other way?
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as os_error:
        # Some network filesystems don't support this and fail with EINVAL.
        # Other error codes (e.g. EIO) shouldn't be silenced.
        if os_error.errno != errno.EINVAL:
            raise
    finally:
        os.close(fd)


def safe_fadvise(fd, offset, len, advice):
    if hasattr(os, "posix_fadvise"):
        advice = getattr(os, "POSIX_FADV_" + advice)
        try:
            os.posix_fadvise(fd, offset, len, advice)
        except OSError:
            # usually, posix_fadvise can't fail for us, but there seem to
            # be failures when running borg under docker on ARM, likely due
            # to a bug outside of borg.
            # also, there is a python wrapper bug, always giving errno = 0.
            # https://github.com/borgbackup/borg/issues/2095
            # as this call is not critical for correct function (just to
            # optimize cache usage), we ignore these errors.
            pass


class SyncFile:
    """
    A file class that is supposed to enable write ordering (one way or another) and data durability after close().

    The degree to which either is possible varies with operating system, file system and hardware.

    This fallback implements a naive and slow way of doing this. On some operating systems it can't actually
    guarantee any of the above, since fsync() doesn't guarantee it. Furthermore it may not be possible at all
    to satisfy the above guarantees on some hardware or operating systems. In these cases we hope that the thorough
    checksumming implemented catches any corrupted data due to misordered, delayed or partial writes.

    Note that POSIX doesn't specify *anything* about power failures (or similar failures). A system that
    routinely loses files or corrupts file on power loss is POSIX compliant.

    Calling SyncFile(path) for an existing path will raise FileExistsError, see comment in __init__.

    TODO: Use F_FULLSYNC on OSX.
    TODO: A Windows implementation should use CreateFile with FILE_FLAG_WRITE_THROUGH.
    """

    def __init__(self, path, *, fd=None, binary=False):
        """
        Open a SyncFile.

        :param path: full path/filename
        :param fd: additionally to path, it is possible to give an already open OS-level fd
               that corresponds to path (like from os.open(path, ...) or os.mkstemp(...))
        :param binary: whether to open in binary mode, default is False.
        """
        mode = "xb" if binary else "x"  # x -> raise FileExists exception in open() if file exists already
        self.path = path
        if fd is None:
            self.f = open(path, mode=mode)  # python file object
        else:
            self.f = os.fdopen(fd, mode=mode)
        self.fd = self.f.fileno()  # OS-level fd

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def write(self, data):
        self.f.write(data)

    def sync(self):
        """
        Synchronize file contents. Everything written prior to sync() must become durable before anything written
        after sync().
        """
        from .. import platform

        self.f.flush()
        platform.fdatasync(self.fd)
        # tell the OS that it does not need to cache what we just wrote,
        # avoids spoiling the cache for the OS and other processes.
        safe_fadvise(self.fd, 0, 0, "DONTNEED")

    def close(self):
        """sync() and close."""
        from .. import platform

        dirname = None
        try:
            dirname = os.path.dirname(self.path)
            self.sync()
        finally:
            self.f.close()
            if dirname:
                platform.sync_dir(dirname)


class SaveFile:
    """
    Update file contents atomically.

    Must be used as a context manager (defining the scope of the transaction).

    On a journaling file system the file contents are always updated
    atomically and won't become corrupted, even on power failures or
    crashes (for caveats see SyncFile).

    SaveFile can safely by used in parallel (e.g. by multiple processes) to write
    to the same target path. Whatever writer finishes last (executes the os.replace
    last) "wins" and has successfully written its content to the target path.
    Internally used temporary files are created in the target directory and are
    named <BASENAME>-<RANDOMCHARS>.tmp and cleaned up in normal and error conditions.
    """

    def __init__(self, path, binary=False):
        self.binary = binary
        self.path = path
        self.dir = os.path.dirname(path)
        self.tmp_prefix = os.path.basename(path) + "-"
        self.tmp_fd = None  # OS-level fd
        self.tmp_fname = None  # full path/filename corresponding to self.tmp_fd
        self.f = None  # python-file-like SyncFile

    def __enter__(self):
        from .. import platform
        from ..helpers.fs import mkstemp_mode

        self.tmp_fd, self.tmp_fname = mkstemp_mode(prefix=self.tmp_prefix, suffix=".tmp", dir=self.dir, mode=0o666)
        self.f = platform.SyncFile(self.tmp_fname, fd=self.tmp_fd, binary=self.binary)
        return self.f

    def __exit__(self, exc_type, exc_val, exc_tb):
        from .. import platform

        self.f.close()  # this indirectly also closes self.tmp_fd
        self.tmp_fd = None
        if exc_type is not None:
            safe_unlink(self.tmp_fname)  # with-body has failed, clean up tmp file
            return  # continue processing the exception normally

        try:
            os.replace(self.tmp_fname, self.path)  # POSIX: atomic rename
        except OSError:
            safe_unlink(self.tmp_fname)  # rename has failed, clean up tmp file
            raise
        finally:
            platform.sync_dir(self.dir)


def swidth(s):
    """terminal output width of string <s>

    For western scripts, this is just len(s), but for cjk glyphs, 2 cells are used.
    """
    return len(s)


# patched socket.getfqdn() - see https://bugs.python.org/issue5004
def getfqdn(name=""):
    """Get fully qualified domain name from name.

    An empty argument is interpreted as meaning the local host.
    """
    name = name.strip()
    if not name or name == "0.0.0.0":
        name = socket.gethostname()
    try:
        addrs = socket.getaddrinfo(name, None, 0, socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
    except OSError:
        pass
    else:
        for addr in addrs:
            if addr[3]:
                name = addr[3]
                break
    return name


# for performance reasons, only determine hostname / fqdn / hostid once.
# XXX this sometimes requires live internet access for issuing a DNS query in the background.
hostname = socket.gethostname()
fqdn = getfqdn(hostname)
# some people put the fqdn into /etc/hostname (which is wrong, should be the short hostname)
# fix this (do the same as "hostname --short" cli command does internally):
hostname = hostname.split(".")[0]

# uuid.getnode() is problematic in some environments (e.g. OpenVZ, see #3968) where the virtual MAC address
# is all-zero. uuid.getnode falls back to returning a random value in that case, which is not what we want.
# thus, we offer BORG_HOST_ID where a user can set an own, unique id for each of his hosts.
hostid = os.environ.get("BORG_HOST_ID")
if not hostid:
    hostid = f"{fqdn}@{uuid.getnode()}"


def get_process_id():
    """
    Return identification tuple (hostname, pid, thread_id) for 'us'.
    This always returns the current pid, which might be different from before, e.g. if daemonize() was used.

    Note: Currently thread_id is *always* zero.
    """
    thread_id = 0
    pid = os.getpid()
    return hostid, pid, thread_id
