import os

from libc cimport errno
from libc.stdlib cimport malloc, free

from .base import MountEntry
from .xattr import _listxattr_inner, _getxattr_inner, _setxattr_inner, split_lstring



cdef extern from "sys/statvfs.h":
    # only the members we use, the header defines the struct (and it maps getvfsstat to the libc
    # symbol of the current struct layout, __getvfsstat90 since NetBSD 9)
    cdef struct statvfs:
        char f_fstypename[32]  # _VFS_NAMELEN
        char f_mntonname[1024]  # _VFS_MNAMELEN
        char f_mntfromname[1024]  # _VFS_MNAMELEN
    int getvfsstat(statvfs *buf, size_t bufsize, int flags)
    int ST_NOWAIT

cdef extern from "sys/extattr.h":
    ssize_t c_extattr_list_file "extattr_list_file" (const char *path, int attrnamespace, void *data, size_t nbytes)
    ssize_t c_extattr_list_link "extattr_list_link" (const char *path, int attrnamespace, void *data, size_t nbytes)
    ssize_t c_extattr_list_fd "extattr_list_fd" (int fd, int attrnamespace, void *data, size_t nbytes)

    ssize_t c_extattr_get_file "extattr_get_file" (const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes)
    ssize_t c_extattr_get_link "extattr_get_link" (const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes)
    ssize_t c_extattr_get_fd "extattr_get_fd" (int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes)

    int c_extattr_set_file "extattr_set_file" (const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes)
    int c_extattr_set_link "extattr_set_link" (const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes)
    int c_extattr_set_fd "extattr_set_fd" (int fd, int attrnamespace, const char *attrname, const void *data, size_t nbytes)

    int EXTATTR_NAMESPACE_USER


# On NetBSD, Borg currently only deals with the USER namespace, as it is unclear
# whether (and, if so, how exactly) it should deal with the SYSTEM namespace.
NS_ID_MAP = {b"user": EXTATTR_NAMESPACE_USER, }


def split_ns(ns_name, default_ns):
    # Split ns_name (which is in the form b"namespace.name") into namespace and name.
    # If there is no namespace given in ns_name, default to default_ns.
    # We also need to deal with "unexpected" namespaces here — they could come
    # from Borg archives made on other operating systems.
    ns_name_tuple = ns_name.split(b".", 1)
    if len(ns_name_tuple) == 2:
        # We have a namespace prefix in the given name.
        ns, name = ns_name_tuple
    else:
        # No namespace given in ns_name (no dot found); maybe data from an old Borg archive.
        ns, name = default_ns, ns_name
    return ns, name


def listxattr(path, *, follow_symlinks=False):
    def func(path, buf, size):
        if isinstance(path, int):
            return c_extattr_list_fd(path, ns_id, <char *> buf, size)
        else:
            if follow_symlinks:
                return c_extattr_list_file(path, ns_id, <char *> buf, size)
            else:
                return c_extattr_list_link(path, ns_id, <char *> buf, size)

    ns = b"user"
    ns_id = NS_ID_MAP[ns]
    n, buf = _listxattr_inner(func, path)
    return [ns + b"." + name for name in split_lstring(buf[:n]) if name]


def getxattr(path, name, *, follow_symlinks=False):
    def func(path, name, buf, size):
        if isinstance(path, int):
            return c_extattr_get_fd(path, ns_id, name, <char *> buf, size)
        else:
            if follow_symlinks:
                return c_extattr_get_file(path, ns_id, name, <char *> buf, size)
            else:
                return c_extattr_get_link(path, ns_id, name, <char *> buf, size)

    ns, name = split_ns(name, b"user")
    ns_id = NS_ID_MAP[ns]  # this will raise a KeyError it the namespace is unsupported
    n, buf = _getxattr_inner(func, path, name)
    return bytes(buf[:n])


def setxattr(path, name, value, *, follow_symlinks=False):
    def func(path, name, value, size):
        if isinstance(path, int):
            return c_extattr_set_fd(path, ns_id, name, <char *> value, size)
        else:
            if follow_symlinks:
                return c_extattr_set_file(path, ns_id, name, <char *> value, size)
            else:
                return c_extattr_set_link(path, ns_id, name, <char *> value, size)

    ns, name = split_ns(name, b"user")
    try:
        ns_id = NS_ID_MAP[ns]  # this will raise a KeyError it the namespace is unsupported
    except KeyError:
        pass
    else:
        _setxattr_inner(func, path, name, value)


def list_mounts():
    """See platform.base.list_mounts, NetBSD implementation via getvfsstat(2)."""
    cdef statvfs *buf
    cdef int count, i
    # getvfsstat returns the number of mounted file systems: all of them if buf is NULL, else as many as
    # fit into buf. ST_NOWAIT: do not ask the file systems for fresh statistics, we only need the names.
    count = getvfsstat(NULL, 0, ST_NOWAIT)
    if count < 0:
        raise OSError(errno.errno, "getvfsstat failed")
    buf = <statvfs *> malloc(count * sizeof(statvfs))
    if buf == NULL:
        raise MemoryError
    try:
        count = getvfsstat(buf, count * sizeof(statvfs), ST_NOWAIT)
        if count < 0:
            raise OSError(errno.errno, "getvfsstat failed")
        return [
            MountEntry(os.fsdecode(buf[i].f_mntfromname), os.fsdecode(buf[i].f_fstypename), os.fsdecode(buf[i].f_mntonname))
            for i in range(count)
        ]
    finally:
        free(buf)
