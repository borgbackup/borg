import os

from .posix import posix_acl_use_stored_uid_gid
from ..helpers import safe_encode, safe_decode
from .xattr import _listxattr_inner, _getxattr_inner, _setxattr_inner, split_lstring

API_VERSION = '1.2_04'

cdef extern from "errno.h":
    int errno
    int EINVAL

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

cdef extern from "sys/types.h":
    int ACL_TYPE_ACCESS
    int ACL_TYPE_DEFAULT
    int ACL_TYPE_NFS4

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
    char *acl_to_text_np(acl_t acl, ssize_t *len, int flags)
    int ACL_TEXT_NUMERIC_IDS
    int ACL_TEXT_APPEND_ID

cdef extern from "unistd.h":
    long lpathconf(const char *path, int name)
    int _PC_ACL_NFS4


def listxattr(path, *, follow_symlinks=False):
    def func(path, buf, size):
        if isinstance(path, int):
            return c_extattr_list_fd(path, EXTATTR_NAMESPACE_USER, <char *> buf, size)
        else:
            if follow_symlinks:
                return c_extattr_list_file(path, EXTATTR_NAMESPACE_USER, <char *> buf, size)
            else:
                return c_extattr_list_link(path, EXTATTR_NAMESPACE_USER, <char *> buf, size)

    n, buf = _listxattr_inner(func, path)
    return [name for name in split_lstring(buf[:n]) if name]


def getxattr(path, name, *, follow_symlinks=False):
    def func(path, name, buf, size):
        if isinstance(path, int):
            return c_extattr_get_fd(path, EXTATTR_NAMESPACE_USER, name, <char *> buf, size)
        else:
            if follow_symlinks:
                return c_extattr_get_file(path, EXTATTR_NAMESPACE_USER, name, <char *> buf, size)
            else:
                return c_extattr_get_link(path, EXTATTR_NAMESPACE_USER, name, <char *> buf, size)

    n, buf = _getxattr_inner(func, path, name)
    return bytes(buf[:n])


def setxattr(path, name, value, *, follow_symlinks=False):
    def func(path, name, value, size):
        if isinstance(path, int):
            return c_extattr_set_fd(path, EXTATTR_NAMESPACE_USER, name, <char *> value, size)
        else:
            if follow_symlinks:
                return c_extattr_set_file(path, EXTATTR_NAMESPACE_USER, name, <char *> value, size)
            else:
                return c_extattr_set_link(path, EXTATTR_NAMESPACE_USER, name, <char *> value, size)

    _setxattr_inner(func, path, name, value)


cdef _get_acl(p, type, item, attribute, flags, fd=None):
    cdef acl_t acl
    cdef char *text
    if fd is not None:
        acl = acl_get_fd_np(fd, type)
    else:
        acl = acl_get_link_np(p, type)
    if acl:
        text = acl_to_text_np(acl, NULL, flags)
        if text:
            item[attribute] = text
            acl_free(text)
        acl_free(acl)


def acl_get(path, item, st, numeric_owner=False, fd=None):
    """Saves ACL Entries

    If `numeric_owner` is True the user/group field is not preserved only uid/gid
    """
    cdef int flags = ACL_TEXT_APPEND_ID
    if isinstance(path, str):
        path = os.fsencode(path)
    ret = lpathconf(path, _PC_ACL_NFS4)
    if ret < 0 and errno == EINVAL:
        return
    flags |= ACL_TEXT_NUMERIC_IDS if numeric_owner else 0
    if ret > 0:
        _get_acl(path, ACL_TYPE_NFS4, item, 'acl_nfs4', flags, fd=fd)
    else:
        _get_acl(path, ACL_TYPE_ACCESS, item, 'acl_access', flags, fd=fd)
        _get_acl(path, ACL_TYPE_DEFAULT, item, 'acl_default', flags, fd=fd)


cdef _set_acl(p, type, item, attribute, numeric_owner=False, fd=None):
    cdef acl_t acl
    text = item.get(attribute)
    if text:
        if numeric_owner and type == ACL_TYPE_NFS4:
            text = _nfs4_use_stored_uid_gid(text)
        elif numeric_owner and type in(ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT):
            text = posix_acl_use_stored_uid_gid(text)
        acl = acl_from_text(<bytes>text)
        if acl:
            if fd is not None:
                acl_set_fd_np(fd, acl, type)
            else:
                acl_set_link_np(p, type, acl)
            acl_free(acl)


cdef _nfs4_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid
    """
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            if entry.startswith('user:') or entry.startswith('group:'):
                fields = entry.split(':')
                entries.append(':'.join(fields[0], fields[5], *fields[2:-1]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def acl_set(path, item, numeric_owner=False, fd=None):
    """Restore ACL Entries

    If `numeric_owner` is True the stored uid/gid is used instead
    of the user/group names
    """
    if isinstance(path, str):
        path = os.fsencode(path)
    _set_acl(path, ACL_TYPE_NFS4, item, 'acl_nfs4', numeric_owner, fd=fd)
    _set_acl(path, ACL_TYPE_ACCESS, item, 'acl_access', numeric_owner, fd=fd)
    _set_acl(path, ACL_TYPE_DEFAULT, item, 'acl_default', numeric_owner, fd=fd)
