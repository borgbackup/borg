"""
xattr support for illumos / Solaris and derivatives.

On these platforms, the extended attributes of a file are regular files inside a hidden
attribute directory attached to that file. The attribute directory is opened by giving
O_XATTR to open(2)/openat(2), see fsattr(7) — xattr names/values map to the names/contents
of the files in there. There are no xattr namespaces, so names are used verbatim.
"""

import errno
import os

from .base import ENOATTR

# CPython exposes os.O_XATTR on Solaris-derived platforms; 0x4000 is its value on illumos
# and Oracle Solaris (belt and braces in case the os module does not have it).
O_XATTR = getattr(os, "O_XATTR", 0x4000)

# "Extended system attributes" maintained by the OS inside every attribute directory
# (e.g. on ZFS) — these are not user-set xattrs, so hide them from listing and refuse
# to write them.
SYSATTR_PREFIX = "SUNWattr_"

# Attribute files can be arbitrarily large — refuse to read values bigger than this
# (the other platforms' xattr support is limited alike, via their Buffer(limit=2**24)).
XATTR_SIZE_LIMIT = 2**24


def _open_attrdir(path, follow_symlinks):
    # Open the hidden attribute directory of *path* (a bytes path or an open file descriptor).
    # O_XATTR is only interpreted by openat() when looking up relative to a file descriptor
    # referring to the file, so for a path, the file itself must be opened first.
    if isinstance(path, int):
        return os.open(".", os.O_RDONLY | O_XATTR, dir_fd=path)
    flags = os.O_RDONLY | os.O_NONBLOCK  # O_NONBLOCK: do not hang on FIFOs
    if not follow_symlinks:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        return os.open(".", os.O_RDONLY | O_XATTR, dir_fd=fd)
    finally:
        os.close(fd)


def listxattr(path, *, follow_symlinks=False):
    try:
        dirfd = _open_attrdir(path, follow_symlinks)
    except OSError as e:
        if e.errno == errno.ELOOP:
            # symlinks cannot have extended attributes on this platform
            return []
        if e.errno == errno.EINVAL:
            # open(2): the filesystem does not support extended attributes
            raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP), path) from None
        raise
    try:
        names = os.listdir(dirfd)
    finally:
        os.close(dirfd)
    return [os.fsencode(name) for name in names if not name.startswith(SYSATTR_PREFIX)]


def getxattr(path, name, *, follow_symlinks=False):
    dirfd = _open_attrdir(path, follow_symlinks)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd)
        except FileNotFoundError:
            # no attribute file with that name -> no such xattr
            raise OSError(ENOATTR, os.strerror(ENOATTR), path) from None
        try:
            if os.fstat(fd).st_size > XATTR_SIZE_LIMIT:
                raise OSError(errno.EFBIG, os.strerror(errno.EFBIG), path)
            chunks = []
            while chunk := os.read(fd, 2**20):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def setxattr(path, name, value, *, follow_symlinks=False):
    name_str = os.fsdecode(name)
    if not name_str or "/" in name_str or "\0" in name_str or name_str in (".", ".."):
        # such a name cannot be the name of an attribute file
        raise OSError(errno.EINVAL, os.strerror(errno.EINVAL), path)
    if name_str.startswith(SYSATTR_PREFIX):
        raise OSError(errno.EPERM, os.strerror(errno.EPERM), path)
    dirfd = _open_attrdir(path, follow_symlinks)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode=0o644, dir_fd=dirfd)
        try:
            mv = memoryview(value)
            while mv:
                mv = mv[os.write(fd, mv) :]
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)
