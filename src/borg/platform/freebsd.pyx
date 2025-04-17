import os
import stat

from libc cimport errno

from .posix import posix_acl_use_stored_uid_gid
from ..helpers import safe_encode, safe_decode
from .xattr import _listxattr_inner, _getxattr_inner, _setxattr_inner, split_lstring

API_VERSION = '1.2_05'

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
    int acl_extended_link_np(const char * path)  # check also: acl_is_trivial_np

cdef extern from "unistd.h":
    long lpathconf(const char *path, int name)
    int _PC_ACL_NFS4
    int _PC_ACL_EXTENDED


# On FreeBSD, borg currently only deals with the USER namespace as it is unclear
# whether (and if so, how exactly) it should deal with the SYSTEM namespace.
NS_ID_MAP = {b"user": EXTATTR_NAMESPACE_USER, }


def split_ns(ns_name, default_ns):
    # split ns_name (which is in the form of b"namespace.name") into namespace and name.
    # if there is no namespace given in ns_name, default to default_ns.
    # note:
    # borg < 1.1.10 on FreeBSD did not prefix the namespace to the names, see #3952.
    # we also need to deal with "unexpected" namespaces here, they could come
    # from borg archives made on other operating systems.
    ns_name_tuple = ns_name.split(b".", 1)
    if len(ns_name_tuple) == 2:
        # we have a namespace prefix in the given name
        ns, name = ns_name_tuple
    else:
        # no namespace given in ns_name (== no dot found), maybe data coming from an old borg archive.
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


cdef _get_acl(p, type, item, attribute, flags, fd=None):
    cdef acl_t acl
    cdef char *text
    if fd is not None:
        acl = acl_get_fd_np(fd, type)
    else:
        acl = acl_get_link_np(p, type)
    if acl == NULL:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(p))
    text = acl_to_text_np(acl, NULL, flags)
    if text == NULL:
        acl_free(acl)
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(p))
    item[attribute] = text
    acl_free(text)
    acl_free(acl)

def acl_get(path, item, st, numeric_ids=False, fd=None):
    """Saves ACL Entries

    If `numeric_ids` is True the user/group field is not preserved only uid/gid
    """
    cdef int flags = ACL_TEXT_APPEND_ID
    flags |= ACL_TEXT_NUMERIC_IDS if numeric_ids else 0
    if isinstance(path, str):
        path = os.fsencode(path)
    ret = acl_extended_link_np(path)
    if ret < 0:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
    if ret == 0:
        # there is no ACL defining permissions other than those defined by the traditional file permission bits.
        return
    ret = lpathconf(path, _PC_ACL_NFS4)
    if ret < 0:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
    nfs4_acl = ret == 1
    if nfs4_acl:
        _get_acl(path, ACL_TYPE_NFS4, item, 'acl_nfs4', flags, fd=fd)
    else:
        _get_acl(path, ACL_TYPE_ACCESS, item, 'acl_access', flags, fd=fd)
        if stat.S_ISDIR(st.st_mode):
            _get_acl(path, ACL_TYPE_DEFAULT, item, 'acl_default', flags, fd=fd)


cdef _set_acl(path, type, item, attribute, numeric_ids=False, fd=None):
    cdef acl_t acl = NULL
    text = item.get(attribute)
    if text:
        if numeric_ids:
            if type == ACL_TYPE_NFS4:
                text = _nfs4_use_stored_uid_gid(text)
            elif type in (ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT):
                text = posix_acl_use_stored_uid_gid(text)
        acl = acl_from_text(<bytes>text)
        if acl == NULL:
            raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
        try:
            if fd is not None:
                if acl_set_fd_np(fd, acl, type) == -1:
                    raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
            else:
                if acl_set_link_np(path, type, acl) == -1:
                    raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
        finally:
            acl_free(acl)


cdef _nfs4_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid
    """
    assert isinstance(acl, bytes)
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            if entry.startswith('user:') or entry.startswith('group:'):
                fields = entry.split(':')
                entries.append(':'.join([fields[0], fields[5]] + fields[2:-1]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def acl_set(path, item, numeric_ids=False, fd=None):
    """Restore ACL Entries

    If `numeric_ids` is True the stored uid/gid is used instead
    of the user/group names
    """
    if isinstance(path, str):
        path = os.fsencode(path)
    ret = lpathconf(path, _PC_ACL_NFS4)
    if ret < 0:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
    if ret == 1:
        _set_acl(path, ACL_TYPE_NFS4, item, 'acl_nfs4', numeric_ids, fd=fd)
    ret = lpathconf(path, _PC_ACL_EXTENDED)
    if ret < 0:
        raise OSError(errno.errno, os.strerror(errno.errno), os.fsdecode(path))
    if ret == 1:
        _set_acl(path, ACL_TYPE_ACCESS, item, 'acl_access', numeric_ids, fd=fd)
        _set_acl(path, ACL_TYPE_DEFAULT, item, 'acl_default', numeric_ids, fd=fd)
