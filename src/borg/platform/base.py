import errno
import os
import socket
import uuid

from borg.helpers import truncate_and_unlink

"""
platform base module
====================

Contains platform API implementations based on what Python itself provides. More specific
APIs are stubs in this module.

When functions in this module use platform APIs themselves they access the public
platform API: that way platform APIs provided by the platform-specific support module
are correctly composed into the base functionality.
"""

API_VERSION = '1.2_02'

fdatasync = getattr(os, 'fdatasync', os.fsync)

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


def acl_get(path, item, st, numeric_owner=False):
    """
    Saves ACL Entries

    If `numeric_owner` is True the user/group field is not preserved only uid/gid
    """


def acl_set(path, item, numeric_owner=False):
    """
    Restore ACL Entries

    If `numeric_owner` is True the stored uid/gid is used instead
    of the user/group names
    """


try:
    from os import lchflags

    def set_flags(path, bsd_flags, fd=None):
        lchflags(path, bsd_flags)
except ImportError:
    def set_flags(path, bsd_flags, fd=None):
        pass


def get_flags(path, st, fd=None):
    """Return BSD-style file flags for path or stat without following symlinks."""
    return getattr(st, 'st_flags', 0)


def sync_dir(path):
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
    if hasattr(os, 'posix_fadvise'):
        advice = getattr(os, 'POSIX_FADV_' + advice)
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

    TODO: Use F_FULLSYNC on OSX.
    TODO: A Windows implementation should use CreateFile with FILE_FLAG_WRITE_THROUGH.
    """

    def __init__(self, path, binary=False):
        mode = 'xb' if binary else 'x'
        self.fd = open(path, mode)
        self.fileno = self.fd.fileno()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def write(self, data):
        self.fd.write(data)

    def sync(self):
        """
        Synchronize file contents. Everything written prior to sync() must become durable before anything written
        after sync().
        """
        from .. import platform
        self.fd.flush()
        platform.fdatasync(self.fileno)
        # tell the OS that it does not need to cache what we just wrote,
        # avoids spoiling the cache for the OS and other processes.
        safe_fadvise(self.fileno, 0, 0, 'DONTNEED')

    def close(self):
        """sync() and close."""
        from .. import platform
        dirname = None
        try:
            dirname = os.path.dirname(self.fd.name)
            self.sync()
        finally:
            self.fd.close()
            if dirname:
                platform.sync_dir(dirname)


class SaveFile:
    """
    Update file contents atomically.

    Must be used as a context manager (defining the scope of the transaction).

    On a journaling file system the file contents are always updated
    atomically and won't become corrupted, even on power failures or
    crashes (for caveats see SyncFile).
    """

    SUFFIX = '.tmp'

    def __init__(self, path, binary=False):
        self.binary = binary
        self.path = path
        self.tmppath = self.path + self.SUFFIX

    def __enter__(self):
        from .. import platform
        try:
            truncate_and_unlink(self.tmppath)
        except FileNotFoundError:
            pass
        self.fd = platform.SyncFile(self.tmppath, self.binary)
        return self.fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        from .. import platform
        self.fd.close()
        if exc_type is not None:
            truncate_and_unlink(self.tmppath)
            return
        os.replace(self.tmppath, self.path)
        platform.sync_dir(os.path.dirname(self.path))


def swidth(s):
    """terminal output width of string <s>

    For western scripts, this is just len(s), but for cjk glyphs, 2 cells are used.
    """
    return len(s)


# patched socket.getfqdn() - see https://bugs.python.org/issue5004
def getfqdn(name=''):
    """Get fully qualified domain name from name.

    An empty argument is interpreted as meaning the local host.
    """
    name = name.strip()
    if not name or name == '0.0.0.0':
        name = socket.gethostname()
    try:
        addrs = socket.getaddrinfo(name, None, 0, socket.SOCK_DGRAM, 0, socket.AI_CANONNAME)
    except socket.error:
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

# uuid.getnode() is problematic in some environments (e.g. OpenVZ, see #3968) where the virtual MAC address
# is all-zero. uuid.getnode falls back to returning a random value in that case, which is not what we want.
# thus, we offer BORG_HOST_ID where a user can set an own, unique id for each of his hosts.
hostid = os.environ.get('BORG_HOST_ID')
if not hostid:
    hostid = '%s@%s' % (fqdn, uuid.getnode())


def get_process_id():
    """
    Return identification tuple (hostname, pid, thread_id) for 'us'.
    This always returns the current pid, which might be different from before, e.g. if daemonize() was used.

    Note: Currently thread_id is *always* zero.
    """
    thread_id = 0
    pid = os.getpid()
    return hostid, pid, thread_id


def get_process_group():
    """
    Return group tuple (hostname, pgid, thread_id) for 'us'.
    """
    raise NotImplementedError


def process_alive(host, pid, thread):
    """
    Check if the (host, pid, thread_id) combination corresponds to a potentially alive process.
    """
    raise NotImplementedError


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    raise NotImplementedError
