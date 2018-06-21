import os
import re
import stat
import subprocess

from ..helpers import posix_acl_use_stored_uid_gid
from ..helpers import user2uid, group2gid
from ..helpers import safe_decode, safe_encode
from .base import SyncFile as BaseSyncFile
from .base import safe_fadvise
from .xattr import _listxattr_inner, _getxattr_inner, _setxattr_inner, split_string0

from libc cimport errno
from libc.stdint cimport int64_t

API_VERSION = '1.2_01'

cdef extern from "attr/xattr.h":
    ssize_t c_listxattr "listxattr" (const char *path, char *list, size_t size)
    ssize_t c_llistxattr "llistxattr" (const char *path, char *list, size_t size)
    ssize_t c_flistxattr "flistxattr" (int filedes, char *list, size_t size)

    ssize_t c_getxattr "getxattr" (const char *path, const char *name, void *value, size_t size)
    ssize_t c_lgetxattr "lgetxattr" (const char *path, const char *name, void *value, size_t size)
    ssize_t c_fgetxattr "fgetxattr" (int filedes, const char *name, void *value, size_t size)

    int c_setxattr "setxattr" (const char *path, const char *name, const void *value, size_t size, int flags)
    int c_lsetxattr "lsetxattr" (const char *path, const char *name, const void *value, size_t size, int flags)
    int c_fsetxattr "fsetxattr" (int filedes, const char *name, const void *value, size_t size, int flags)

cdef extern from "sys/types.h":
    int ACL_TYPE_ACCESS
    int ACL_TYPE_DEFAULT

cdef extern from "sys/acl.h":
    ctypedef struct _acl_t:
        pass
    ctypedef _acl_t *acl_t

    int acl_free(void *obj)
    acl_t acl_get_file(const char *path, int type)
    int acl_set_file(const char *path, int type, acl_t acl)
    acl_t acl_from_text(const char *buf)
    char *acl_to_text(acl_t acl, ssize_t *len)

cdef extern from "acl/libacl.h":
    int acl_extended_file(const char *path)

cdef extern from "fcntl.h":
    int sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags)
    unsigned int SYNC_FILE_RANGE_WRITE
    unsigned int SYNC_FILE_RANGE_WAIT_BEFORE
    unsigned int SYNC_FILE_RANGE_WAIT_AFTER

cdef extern from "linux/fs.h":
    # ioctls
    int FS_IOC_SETFLAGS
    int FS_IOC_GETFLAGS

    # inode flags
    int FS_NODUMP_FL
    int FS_IMMUTABLE_FL
    int FS_APPEND_FL
    int FS_COMPR_FL

cdef extern from "sys/ioctl.h":
    int ioctl(int fildes, int request, ...)

cdef extern from "unistd.h":
    int _SC_PAGESIZE
    long sysconf(int name)

cdef extern from "string.h":
    char *strerror(int errnum)

_comment_re = re.compile(' *#.*', re.M)


def listxattr(path, *, follow_symlinks=True):
    def func(path, buf, size):
        cdef char *buffer = <char *> buf
        if isinstance(path, int):
            return c_flistxattr(path, buffer, size)
        else:
            if follow_symlinks:
                return c_listxattr(path, buffer, size)
            else:
                return c_llistxattr(path, buffer, size)

    n, buf = _listxattr_inner(func, path)
    return [os.fsdecode(name) for name in split_string0(buf[:n])
            if name and not name.startswith(b'system.posix_acl_')]


def getxattr(path, name, *, follow_symlinks=True):
    def func(path, name, buf, size):
        cdef char *buffer = <char *> buf
        if isinstance(path, int):
            return c_fgetxattr(path, name, buffer, size)
        else:
            if follow_symlinks:
                return c_getxattr(path, name, buffer, size)
            else:
                return c_lgetxattr(path, name, buffer, size)

    n, buf = _getxattr_inner(func, path, name)
    return buf[:n] or None


def setxattr(path, name, value, *, follow_symlinks=True):
    def func(path, name, value, size):
        cdef char *val = NULL if value is None else <char *> value
        flags = 0
        if isinstance(path, int):
            return c_fsetxattr(path, name, val, size, flags)
        else:
            if follow_symlinks:
                return c_setxattr(path, name, val, size, flags)
            else:
                return c_lsetxattr(path, name, val, size, flags)

    _setxattr_inner(func, path, name, value)


BSD_TO_LINUX_FLAGS = {
    stat.UF_NODUMP: FS_NODUMP_FL,
    stat.UF_IMMUTABLE: FS_IMMUTABLE_FL,
    stat.UF_APPEND: FS_APPEND_FL,
    stat.UF_COMPRESSED: FS_COMPR_FL,
}


def set_flags(path, bsd_flags, fd=None):
    if fd is None:
        st = os.stat(path, follow_symlinks=False)
        if stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            # see comment in get_flags()
            return
    cdef int flags = 0
    for bsd_flag, linux_flag in BSD_TO_LINUX_FLAGS.items():
        if bsd_flags & bsd_flag:
            flags |= linux_flag
    open_fd = fd is None
    if open_fd:
        fd = os.open(path, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        if ioctl(fd, FS_IOC_SETFLAGS, &flags) == -1:
            error_number = errno.errno
            if error_number != errno.EOPNOTSUPP:
                raise OSError(error_number, strerror(error_number).decode(), path)
    finally:
        if open_fd:
            os.close(fd)


def get_flags(path, st):
    if stat.S_ISBLK(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        # avoid opening devices files - trying to open non-present devices can be rather slow.
        # avoid opening symlinks, O_NOFOLLOW would make the open() fail anyway.
        return 0
    cdef int linux_flags
    try:
        fd = os.open(path, os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    except OSError:
        return 0
    try:
        if ioctl(fd, FS_IOC_GETFLAGS, &linux_flags) == -1:
            return 0
    finally:
        os.close(fd)
    bsd_flags = 0
    for bsd_flag, linux_flag in BSD_TO_LINUX_FLAGS.items():
        if linux_flags & linux_flag:
            bsd_flags |= bsd_flag
    return bsd_flags


def acl_use_local_uid_gid(acl):
    """Replace the user/group field with the local uid/gid if possible
    """
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if fields[0] == 'user' and fields[1]:
                fields[1] = str(user2uid(fields[1], fields[3]))
            elif fields[0] == 'group' and fields[1]:
                fields[1] = str(group2gid(fields[1], fields[3]))
            entries.append(':'.join(fields[:3]))
    return safe_encode('\n'.join(entries))


cdef acl_append_numeric_ids(acl):
    """Extend the "POSIX 1003.1e draft standard 17" format with an additional uid/gid field
    """
    entries = []
    for entry in _comment_re.sub('', safe_decode(acl)).split('\n'):
        if entry:
            type, name, permission = entry.split(':')
            if name and type == 'user':
                entries.append(':'.join([type, name, permission, str(user2uid(name, name))]))
            elif name and type == 'group':
                entries.append(':'.join([type, name, permission, str(group2gid(name, name))]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


cdef acl_numeric_ids(acl):
    """Replace the "POSIX 1003.1e draft standard 17" user/group field with uid/gid
    """
    entries = []
    for entry in _comment_re.sub('', safe_decode(acl)).split('\n'):
        if entry:
            type, name, permission = entry.split(':')
            if name and type == 'user':
                uid = str(user2uid(name, name))
                entries.append(':'.join([type, uid, permission, uid]))
            elif name and type == 'group':
                gid = str(group2gid(name, name))
                entries.append(':'.join([type, gid, permission, gid]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def acl_get(path, item, st, numeric_owner=False):
    cdef acl_t default_acl = NULL
    cdef acl_t access_acl = NULL
    cdef char *default_text = NULL
    cdef char *access_text = NULL

    p = <bytes>os.fsencode(path)
    if stat.S_ISLNK(st.st_mode) or acl_extended_file(p) <= 0:
        return
    if numeric_owner:
        converter = acl_numeric_ids
    else:
        converter = acl_append_numeric_ids
    try:
        access_acl = acl_get_file(p, ACL_TYPE_ACCESS)
        if access_acl:
            access_text = acl_to_text(access_acl, NULL)
            if access_text:
                item['acl_access'] = converter(access_text)
        default_acl = acl_get_file(p, ACL_TYPE_DEFAULT)
        if default_acl:
            default_text = acl_to_text(default_acl, NULL)
            if default_text:
                item['acl_default'] = converter(default_text)
    finally:
        acl_free(default_text)
        acl_free(default_acl)
        acl_free(access_text)
        acl_free(access_acl)


def acl_set(path, item, numeric_owner=False):
    cdef acl_t access_acl = NULL
    cdef acl_t default_acl = NULL

    p = <bytes>os.fsencode(path)
    if numeric_owner:
        converter = posix_acl_use_stored_uid_gid
    else:
        converter = acl_use_local_uid_gid
    access_text = item.get('acl_access')
    default_text = item.get('acl_default')
    if access_text:
        try:
            access_acl = acl_from_text(<bytes>converter(access_text))
            if access_acl:
                acl_set_file(p, ACL_TYPE_ACCESS, access_acl)
        finally:
            acl_free(access_acl)
    if default_text:
        try:
            default_acl = acl_from_text(<bytes>converter(default_text))
            if default_acl:
                acl_set_file(p, ACL_TYPE_DEFAULT, default_acl)
        finally:
            acl_free(default_acl)

cdef _sync_file_range(fd, offset, length, flags):
    assert offset & PAGE_MASK == 0, "offset %d not page-aligned" % offset
    assert length & PAGE_MASK == 0, "length %d not page-aligned" % length
    if sync_file_range(fd, offset, length, flags) != 0:
        raise OSError(errno.errno, os.strerror(errno.errno))
    safe_fadvise(fd, offset, length, 'DONTNEED')

cdef unsigned PAGE_MASK = sysconf(_SC_PAGESIZE) - 1


class SyncFile(BaseSyncFile):
    """
    Implemented using sync_file_range for asynchronous write-out and fdatasync for actual durability.

    "write-out" means that dirty pages (= data that was written) are submitted to an I/O queue and will be send to
    disk in the immediate future.
    """

    def __init__(self, path, binary=False):
        super().__init__(path, binary)
        self.offset = 0
        self.write_window = (16 * 1024 ** 2) & ~PAGE_MASK
        self.last_sync = 0
        self.pending_sync = None

    def write(self, data):
        self.offset += self.fd.write(data)
        offset = self.offset & ~PAGE_MASK
        if offset >= self.last_sync + self.write_window:
            self.fd.flush()
            _sync_file_range(self.fileno, self.last_sync, offset - self.last_sync, SYNC_FILE_RANGE_WRITE)
            if self.pending_sync is not None:
                _sync_file_range(self.fileno, self.pending_sync, self.last_sync - self.pending_sync,
                                 SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WAIT_AFTER)
            self.pending_sync = self.last_sync
            self.last_sync = offset

    def sync(self):
        self.fd.flush()
        os.fdatasync(self.fileno)
        # tell the OS that it does not need to cache what we just wrote,
        # avoids spoiling the cache for the OS and other processes.
        safe_fadvise(self.fileno, 0, 0, 'DONTNEED')
