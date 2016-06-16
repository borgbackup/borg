import os

"""
platform base module
====================

Contains platform API implementations based on what Python itself provides. More specific
APIs are stubs in this module.

When functions in this module use platform APIs themselves they access the public
platform API: that way platform APIs provided by the platform-specific support module
are correctly composed into the base functionality.
"""

API_VERSION = 3

fdatasync = getattr(os, 'fdatasync', os.fsync)


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


def get_flags(path, st):
    """Return BSD-style file flags for path or stat without following symlinks."""
    return getattr(st, 'st_flags', 0)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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

    def __init__(self, path):
        self.fd = open(path, 'xb')
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
        if hasattr(os, 'posix_fadvise'):
            os.posix_fadvise(self.fileno, 0, 0, os.POSIX_FADV_DONTNEED)

    def close(self):
        """sync() and close."""
        from .. import platform
        self.sync()
        self.fd.close()
        platform.sync_dir(os.path.dirname(self.fd.name))


def swidth(s):
    """terminal output width of string <s>

    For western scripts, this is just len(s), but for cjk glyphs, 2 cells are used.
    """
    return len(s)
