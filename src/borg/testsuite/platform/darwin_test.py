import os
import tempfile

from ...platform import acl_get, acl_set
from .platform_test import skipif_not_darwin, skipif_fakeroot_detected, skipif_acls_not_working

# set module-level skips
pytestmark = [skipif_not_darwin, skipif_fakeroot_detected]


def get_acl(path, numeric_ids=False):
    item = {}
    acl_get(path, item, os.stat(path), numeric_ids=numeric_ids)
    return item


def set_acl(path, acl, numeric_ids=False):
    item = {"acl_extended": acl}
    acl_set(path, item, numeric_ids=numeric_ids)


@skipif_acls_not_working
def test_extended_acl():
    file = tempfile.NamedTemporaryFile()
    assert get_acl(file.name) == {}
    set_acl(
        file.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=False,
    )
    assert b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014:staff:20:allow:read" in get_acl(file.name)["acl_extended"]
    assert b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read" in get_acl(file.name)["acl_extended"]

    file2 = tempfile.NamedTemporaryFile()
    set_acl(
        file2.name,
        b"!#acl 1\n"
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:staff:0:allow:read\n"
        b"user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000:root:0:allow:read\n",
        numeric_ids=True,
    )
    assert b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000:wheel:0:allow:read" in get_acl(file2.name)["acl_extended"]
    assert (
        b"group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000000::0:allow:read"
        in get_acl(file2.name, numeric_ids=True)["acl_extended"]
    )
