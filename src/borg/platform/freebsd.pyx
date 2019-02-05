# cython: language_level=3

import os

from ..helpers import posix_acl_use_stored_uid_gid
from ..helpers import safe_encode, safe_decode
from .posix import swidth

API_VERSION = '1.1_04'

cdef extern from "errno.h":
    int errno
    int EINVAL

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
    int acl_set_link_np(const char *path, int type, acl_t acl)
    acl_t acl_from_text(const char *buf)
    char *acl_to_text_np(acl_t acl, ssize_t *len, int flags)
    int ACL_TEXT_NUMERIC_IDS
    int ACL_TEXT_APPEND_ID

cdef extern from "unistd.h":
    long lpathconf(const char *path, int name)
    int _PC_ACL_NFS4


cdef _get_acl(p, type, item, attribute, int flags):
    cdef acl_t acl
    cdef char *text
    acl = acl_get_link_np(p, type)
    if acl:
        text = acl_to_text_np(acl, NULL, flags)
        if text:
            item[attribute] = text
            acl_free(text)
        acl_free(acl)


def acl_get(path, item, st, numeric_owner=False):
    """Saves ACL Entries

    If `numeric_owner` is True the user/group field is not preserved only uid/gid
    """
    cdef int flags = ACL_TEXT_APPEND_ID
    p = os.fsencode(path)
    ret = lpathconf(p, _PC_ACL_NFS4)
    if ret < 0 and errno == EINVAL:
        return
    flags |= ACL_TEXT_NUMERIC_IDS if numeric_owner else 0
    if ret > 0:
        _get_acl(p, ACL_TYPE_NFS4, item, 'acl_nfs4', flags)
    else:
        _get_acl(p, ACL_TYPE_ACCESS, item, 'acl_access', flags)
        _get_acl(p, ACL_TYPE_DEFAULT, item, 'acl_default', flags)


cdef _set_acl(p, type, item, attribute, numeric_owner=False):
    cdef acl_t acl
    text = item.get(attribute)
    if text:
        if numeric_owner and type == ACL_TYPE_NFS4:
            text = _nfs4_use_stored_uid_gid(text)
        elif numeric_owner and type in(ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT):
            text = posix_acl_use_stored_uid_gid(text)
        acl = acl_from_text(<bytes>text)
        if acl:
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


def acl_set(path, item, numeric_owner=False):
    """Restore ACL Entries

    If `numeric_owner` is True the stored uid/gid is used instead
    of the user/group names
    """
    p = os.fsencode(path)
    _set_acl(p, ACL_TYPE_NFS4, item, 'acl_nfs4', numeric_owner)
    _set_acl(p, ACL_TYPE_ACCESS, item, 'acl_access', numeric_owner)
    _set_acl(p, ACL_TYPE_DEFAULT, item, 'acl_default', numeric_owner)
