import os
from attic.helpers import acl_use_local_uid_gid, acl_use_stored_uid_gid, user2uid, group2gid

API_VERSION = 1

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
    int acl_extended_file_nofollow(const char *path)


def acl_append_numeric_ids(acl):
    """Extend the "POSIX 1003.1e draft standard 17" format with an additional uid/gid field
    """
    entries = []
    for entry in acl.decode('ascii').split('\n'):
        if entry:
            type, name, permission = entry.split(':')
            if name and type == 'user':
                entries.append(':'.join([type, name, permission, str(user2uid(name, name))]))
            elif name and type == 'group':
                entries.append(':'.join([type, name, permission, str(group2gid(name, name))]))
            else:
                entries.append(entry)
    return ('\n'.join(entries)).encode('ascii')


def acl_numeric_ids(acl):
    """Replace the "POSIX 1003.1e draft standard 17" user/group field with uid/gid
    """
    entries = []
    for entry in acl.decode('ascii').split('\n'):
        if entry:
            type, name, permission = entry.split(':')
            if name and type == 'user':
                entries.append(':'.join([type, str(user2uid(name, name)), permission]))
            elif name and type == 'group':
                entries.append(':'.join([type, str(group2gid(name, name)), permission]))
            else:
                entries.append(entry)
    return ('\n'.join(entries)).encode('ascii')


def acl_get(path, item, numeric_owner=False):
    """Saves ACL Entries

    If `numeric_owner` is True the user/group field is not preserved only uid/gid
    """
    cdef acl_t default_acl = NULL
    cdef acl_t access_acl = NULL
    cdef char *default_text = NULL
    cdef char *access_text = NULL

    if acl_extended_file_nofollow(<bytes>os.fsencode(path)) <= 0:
        return
    if numeric_owner:
        converter = acl_numeric_ids
    else:
        converter = acl_append_numeric_ids
    try:
        access_acl = acl_get_file(<bytes>os.fsencode(path), ACL_TYPE_ACCESS)
        if access_acl:
            access_text = acl_to_text(access_acl, NULL)
            if access_text:
                item[b'acl_access'] = acl_append_numeric_ids(access_text)
        default_acl = acl_get_file(<bytes>os.fsencode(path), ACL_TYPE_DEFAULT)
        if default_acl:
            default_text = acl_to_text(default_acl, NULL)
            if default_text:
                item[b'acl_default'] = acl_append_numeric_ids(default_text)
    finally:
        acl_free(default_text)
        acl_free(default_acl)
        acl_free(access_text)
        acl_free(access_acl)


def acl_set(path, item, numeric_owner=False):
    """Restore ACL Entries

    If `numeric_owner` is True the stored uid/gid is used instead
    of the user/group names
    """
    cdef acl_t access_acl = NULL
    cdef acl_t default_acl = NULL
    if numeric_owner:
        converter = acl_use_stored_uid_gid
    else:
        converter = acl_use_local_uid_gid
    access_text = item.get(b'acl_access')
    default_text = item.get(b'acl_default')
    if access_text:
        try:
            access_acl = acl_from_text(<bytes>converter(access_text))
            if access_acl:
                acl_set_file(<bytes>os.fsencode(path), ACL_TYPE_ACCESS, access_acl)
        finally:
            acl_free(access_acl)
    if default_text:
        try:
            default_acl = acl_from_text(<bytes>converter(default_text))
            if default_acl:
                acl_set_file(<bytes>os.fsencode(path), ACL_TYPE_DEFAULT, default_acl)
        finally:
            acl_free(default_acl)
