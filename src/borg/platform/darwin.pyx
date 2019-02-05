# cython: language_level=3

import os

from ..helpers import user2uid, group2gid
from ..helpers import safe_decode, safe_encode
from .posix import swidth

API_VERSION = '1.1_04'

cdef extern from "sys/acl.h":
    ctypedef struct _acl_t:
        pass
    ctypedef _acl_t *acl_t

    int acl_free(void *obj)
    acl_t acl_get_link_np(const char *path, int type)
    int acl_set_link_np(const char *path, int type, acl_t acl)
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
            item['acl_extended'] = _remove_non_numeric_identifier(text)
        else:
            item['acl_extended'] = text
    finally:
        acl_free(text)
        acl_free(acl)


def acl_set(path, item, numeric_owner=False):
    cdef acl_t acl = NULL
    acl_text = item.get('acl_extended')
    if acl_text is not None:
        try:
            if numeric_owner:
                acl = acl_from_text(acl_text)
            else:
                acl = acl_from_text(<bytes>_remove_numeric_id_if_possible(acl_text))
            if acl == NULL:
                return
            if acl_set_link_np(<bytes>os.fsencode(path), ACL_TYPE_EXTENDED, acl):
                return
        finally:
            acl_free(acl)
