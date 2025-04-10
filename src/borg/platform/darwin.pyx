import os

from libc.stdint cimport uint32_t
from libc cimport errno
from posix.time cimport timespec

from .posix import user2uid, group2gid
from ..helpers import safe_decode, safe_encode
from .xattr import _listxattr_inner, _getxattr_inner, _setxattr_inner, split_string0

API_VERSION = '1.2_05'

cdef extern from *:
    """
    #ifdef _DARWIN_FEATURE_64_BIT_INODE
    #define DARWIN_FEATURE_64_BIT_INODE_DEFINED 1
    #else
    #define DARWIN_FEATURE_64_BIT_INODE_DEFINED 0
    #endif
    """
    int DARWIN_FEATURE_64_BIT_INODE_DEFINED

is_darwin_feature_64_bit_inode = DARWIN_FEATURE_64_BIT_INODE_DEFINED != 0

cdef extern from "sys/xattr.h":
    ssize_t c_listxattr "listxattr" (const char *path, char *list, size_t size, int flags)
    ssize_t c_flistxattr "flistxattr" (int filedes, char *list, size_t size, int flags)

    ssize_t c_getxattr "getxattr" (const char *path, const char *name, void *value, size_t size, uint32_t pos, int flags)
    ssize_t c_fgetxattr "fgetxattr" (int filedes, const char *name, void *value, size_t size, uint32_t pos, int flags)

    int c_setxattr "setxattr" (const char *path, const char *name, const void *value, size_t size, uint32_t pos, int flags)
    int c_fsetxattr "fsetxattr" (int filedes, const char *name, const void *value, size_t size, uint32_t pos, int flags)

    int XATTR_NOFOLLOW

cdef int XATTR_NOFLAGS = 0x0000

cdef extern from "sys/acl.h":
    ctypedef struct _acl_t:
        pass
    ctypedef _acl_t *acl_t

    int acl_free(void *obj)
    acl_t acl_get_link_np(const char *path, int type)
    acl_t acl_get_fd_np(int fd, int type)
    int acl_set_link_np(const char *path, int type, acl_t acl)
    int acl_set_fd_np(int fd, acl_t acl, int type)
    acl_t acl_from_text(const char *buf)
    char *acl_to_text(acl_t acl, ssize_t *len_p)
    int ACL_TYPE_EXTENDED

cdef extern from "sys/stat.h":
    cdef struct stat:
        timespec st_birthtimespec

    int c_stat "stat" (const char *path, stat *buf)
    int c_lstat "lstat" (const char *path, stat *buf)
    int c_fstat "fstat" (int filedes, stat *buf)


def listxattr(path, *, follow_symlinks=False):
    def func(path, buf, size):
        if isinstance(path, int):
            return c_flistxattr(path, <char *> buf, size, XATTR_NOFLAGS)
        else:
            if follow_symlinks:
                return c_listxattr(path, <char *> buf, size, XATTR_NOFLAGS)
            else:
                return c_listxattr(path, <char *> buf, size, XATTR_NOFOLLOW)

    n, buf = _listxattr_inner(func, path)
    return [name for name in split_string0(buf[:n]) if name]


def getxattr(path, name, *, follow_symlinks=False):
    def func(path, name, buf, size):
        if isinstance(path, int):
            return c_fgetxattr(path, name, <char *> buf, size, 0, XATTR_NOFLAGS)
        else:
            if follow_symlinks:
                return c_getxattr(path, name, <char *> buf, size, 0, XATTR_NOFLAGS)
            else:
                return c_getxattr(path, name, <char *> buf, size, 0, XATTR_NOFOLLOW)

    n, buf = _getxattr_inner(func, path, name)
    return bytes(buf[:n])


def setxattr(path, name, value, *, follow_symlinks=False):
    def func(path, name, value, size):
        if isinstance(path, int):
            return c_fsetxattr(path, name, <char *> value, size, 0, XATTR_NOFLAGS)
        else:
            if follow_symlinks:
                return c_setxattr(path, name, <char *> value, size, 0, XATTR_NOFLAGS)
            else:
                return c_setxattr(path, name, <char *> value, size, 0, XATTR_NOFOLLOW)

    _setxattr_inner(func, path, name, value)


def _remove_numeric_id_if_possible(acl):
    """Replace the user/group field with the local uid/gid if possible
    """
    assert isinstance(acl, bytes)
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if fields[0] == 'user':
                if user2uid(fields[2]) is not None:
                    fields[1] = fields[3] = ''
            elif fields[0] == 'group':
                if group2gid(fields[2]) is not None:
                    fields[1] = fields[3] = ''
            entries.append(':'.join(fields))
    return safe_encode('\n'.join(entries))


def _remove_non_numeric_identifier(acl):
    """Remove user and group names from the acl
    """
    assert isinstance(acl, bytes)
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if fields[0] in ('user', 'group'):
                fields[2] = ''
                entries.append(':'.join(fields))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def acl_get(path, item, st, numeric_ids=False, fd=None):
    cdef acl_t acl = NULL
    cdef char *text = NULL
    if isinstance(path, str):
        path = os.fsencode(path)
    try:
        if fd is not None:
            acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED)
        else:
            acl = acl_get_link_np(path, ACL_TYPE_EXTENDED)
        if acl == NULL:
            if errno.errno == errno.ENOENT:
                # macOS weirdness: if a file has no ACLs, it sets errno to ENOENT. :-(
                return
            raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
        text = acl_to_text(acl, NULL)
        if text == NULL:
            raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
        if numeric_ids:
            item['acl_extended'] = _remove_non_numeric_identifier(text)
        else:
            item['acl_extended'] = text
    finally:
        acl_free(text)
        acl_free(acl)


def acl_set(path, item, numeric_ids=False, fd=None):
    cdef acl_t acl = NULL
    acl_text = item.get('acl_extended')
    if acl_text is not None:
        try:
            if isinstance(path, str):
                path = os.fsencode(path)
            if numeric_ids:
                acl = acl_from_text(acl_text)
            else:
                acl = acl_from_text(<bytes>_remove_numeric_id_if_possible(acl_text))
            if acl == NULL:
                raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
            if fd is not None:
                if acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == -1:
                    raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
            else:
                if acl_set_link_np(path, ACL_TYPE_EXTENDED, acl) == -1:
                    raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
        finally:
            acl_free(acl)


def _get_birthtime_ns(path, follow_symlinks=False):
    if isinstance(path, str):
        path = os.fsencode(path)
    cdef stat stat_info
    cdef int result
    if isinstance(path, int):
        result = c_fstat(path, &stat_info)
    else:
        if follow_symlinks:
            result = c_stat(path, &stat_info)
        else:
            result = c_lstat(path, &stat_info)
    if result != 0:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
    return stat_info.st_birthtimespec.tv_sec * 1_000_000_000 + stat_info.st_birthtimespec.tv_nsec
