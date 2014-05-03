import os
API_VERSION = 1

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


def acl_get(path, item, numeric_owner=False):
    cdef acl_t acl = NULL
    cdef char *text = NULL
    try:
        acl = acl_get_link_np(<bytes>os.fsencode(path), ACL_TYPE_EXTENDED)
        if acl == NULL:
            return
        text = acl_to_text(acl, NULL)
        if text == NULL:
            return
        item[b'acl_extended'] = text
    finally:
        acl_free(text)
        acl_free(acl)


def acl_set(path, item, numeric_owner=False):
    cdef acl_t acl = NULL
    try:
        try:
            acl = acl_from_text(item[b'acl_extended'])
        except KeyError:
            return
        if acl == NULL:
            return
        if acl_set_link_np(<bytes>os.fsencode(path), ACL_TYPE_EXTENDED, acl):
            return
    finally:
        acl_free(acl)

