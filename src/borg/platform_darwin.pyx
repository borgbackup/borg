import os
from .helpers import user2uid, group2gid, safe_decode, safe_encode

API_VERSION = 2

cdef extern from "sys/acl.h":
    ctypedef struct _acl_t:
        pass
    ctypedef _acl_t *acl_t

    int acl_free(void *obj)
    acl_t acl_get_link_np(const char *path, int type)
    acl_t acl_set_link_np(const char *path, int type, acl_t acl)
    acl_t acl_from_text(const char *buf)
    char *acl_to_text(acl_t acl, ssize_t *len_p)
    int ACL_TYPE_EXTENDED


def _remove_numeric_id_if_possible(acl):
    """Replace the user/group field with the local uid/gid if possible
    """
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


def acl_get(path, item, st, numeric_owner=False):
    cdef acl_t acl = NULL
    cdef char *text = NULL
    try:
        acl = acl_get_link_np(<bytes>os.fsencode(path), ACL_TYPE_EXTENDED)
        if acl == NULL:
            return
        text = acl_to_text(acl, NULL)
        if text == NULL:
            return
        if numeric_owner:
            item[b'acl_extended'] = _remove_non_numeric_identifier(text)
        else:
            item[b'acl_extended'] = text
    finally:
        acl_free(text)
        acl_free(acl)


def acl_set(path, item, numeric_owner=False):
    cdef acl_t acl = NULL
    try:
        try:
            if numeric_owner:
                acl = acl_from_text(item[b'acl_extended'])
            else:
                acl = acl_from_text(<bytes>_remove_numeric_id_if_possible(item[b'acl_extended']))
        except KeyError:
            return
        if acl == NULL:
            return
        if acl_set_link_np(<bytes>os.fsencode(path), ACL_TYPE_EXTENDED, acl):
            return
    finally:
        acl_free(acl)

