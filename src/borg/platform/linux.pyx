import os
import re
import stat
import subprocess

from ..helpers import posix_acl_use_stored_uid_gid
from ..helpers import user2uid, group2gid
from ..helpers import safe_decode, safe_encode
from .base import SyncFile as BaseSyncFile
from .base import safe_fadvise
from .posix import swidth

from libc cimport errno
from libc.stdint cimport int64_t

API_VERSION = '1.1_01'

cdef extern from "sys/types.h":
    int ACL_TYPE_ACCESS
    int ACL_TYPE_DEFAULT

cdef extern from "sys/acl.h":
    ctypedef struct _acl_t:
        pass
    ctypedef _acl_t *acl_t

    int acl_free(void *obj)
    acl_t acl_get_file(const char *path, int type)
    acl_t acl_set_file(const char *path, int type, acl_t acl)
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


BSD_TO_LINUX_FLAGS = {
    stat.UF_NODUMP: FS_NODUMP_FL,
    stat.UF_IMMUTABLE: FS_IMMUTABLE_FL,
    stat.UF_APPEND: FS_APPEND_FL,
    stat.UF_COMPRESSED: FS_COMPR_FL,
}


def set_flags(path, bsd_flags, fd=None):
    if fd is None and stat.S_ISLNK(os.lstat(path).st_mode):
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


def umount(mountpoint):
    return subprocess.call(['fusermount', '-u', mountpoint])
