"""A basic extended attributes (xattr) implementation for Linux and MacOS X
"""
import errno
import os
import sys
import tempfile
from ctypes import CDLL, create_string_buffer, c_ssize_t, c_size_t, c_char_p, c_int, c_uint32, get_errno
from ctypes.util import find_library


def is_enabled(path=None):
    """Determine if xattr is enabled on the filesystem
    """
    with tempfile.NamedTemporaryFile(dir=path, prefix='borg-tmp') as fd:
        try:
            setxattr(fd.fileno(), 'user.name', b'value')
        except OSError:
            return False
        return getxattr(fd.fileno(), 'user.name') == b'value'


def get_all(path, follow_symlinks=True):
    try:
        return dict((name, getxattr(path, name, follow_symlinks=follow_symlinks))
                    for name in listxattr(path, follow_symlinks=follow_symlinks))
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EPERM):
            return {}


libc = CDLL(find_library('c'), use_errno=True)


def _check(rv, path=None):
    if rv < 0:
        raise OSError(get_errno(), path)
    return rv

if sys.platform.startswith('linux'):
    libc.llistxattr.argtypes = (c_char_p, c_char_p, c_size_t)
    libc.llistxattr.restype = c_ssize_t
    libc.flistxattr.argtypes = (c_int, c_char_p, c_size_t)
    libc.flistxattr.restype = c_ssize_t
    libc.lsetxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t, c_int)
    libc.lsetxattr.restype = c_int
    libc.fsetxattr.argtypes = (c_int, c_char_p, c_char_p, c_size_t, c_int)
    libc.fsetxattr.restype = c_int
    libc.lgetxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t)
    libc.lgetxattr.restype = c_ssize_t
    libc.fgetxattr.argtypes = (c_int, c_char_p, c_char_p, c_size_t)
    libc.fgetxattr.restype = c_ssize_t

    def listxattr(path, *, follow_symlinks=True):
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.flistxattr
        elif follow_symlinks:
            func = libc.listxattr
        else:
            func = libc.llistxattr
        n = _check(func(path, None, 0), path)
        if n == 0:
            return []
        namebuf = create_string_buffer(n)
        n2 = _check(func(path, namebuf, n), path)
        if n2 != n:
            raise Exception('listxattr failed')
        return [os.fsdecode(name) for name in namebuf.raw.split(b'\0')[:-1] if not name.startswith(b'system.posix_acl_')]

    def getxattr(path, name, *, follow_symlinks=True):
        name = os.fsencode(name)
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.fgetxattr
        elif follow_symlinks:
            func = libc.getxattr
        else:
            func = libc.lgetxattr
        n = _check(func(path, name, None, 0))
        if n == 0:
            return
        valuebuf = create_string_buffer(n)
        n2 = _check(func(path, name, valuebuf, n), path)
        if n2 != n:
            raise Exception('getxattr failed')
        return valuebuf.raw

    def setxattr(path, name, value, *, follow_symlinks=True):
        name = os.fsencode(name)
        value = value and os.fsencode(value)
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.fsetxattr
        elif follow_symlinks:
            func = libc.setxattr
        else:
            func = libc.lsetxattr
        _check(func(path, name, value, len(value) if value else 0, 0), path)

elif sys.platform == 'darwin':
    libc.listxattr.argtypes = (c_char_p, c_char_p, c_size_t, c_int)
    libc.listxattr.restype = c_ssize_t
    libc.flistxattr.argtypes = (c_int, c_char_p, c_size_t)
    libc.flistxattr.restype = c_ssize_t
    libc.setxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t, c_uint32, c_int)
    libc.setxattr.restype = c_int
    libc.fsetxattr.argtypes = (c_int, c_char_p, c_char_p, c_size_t, c_uint32, c_int)
    libc.fsetxattr.restype = c_int
    libc.getxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t, c_uint32, c_int)
    libc.getxattr.restype = c_ssize_t
    libc.fgetxattr.argtypes = (c_int, c_char_p, c_char_p, c_size_t, c_uint32, c_int)
    libc.fgetxattr.restype = c_ssize_t

    XATTR_NOFOLLOW = 0x0001

    def listxattr(path, *, follow_symlinks=True):
        func = libc.listxattr
        flags = 0
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.flistxattr
        elif not follow_symlinks:
            flags = XATTR_NOFOLLOW
        n = _check(func(path, None, 0, flags), path)
        if n == 0:
            return []
        namebuf = create_string_buffer(n)
        n2 = _check(func(path, namebuf, n, flags), path)
        if n2 != n:
            raise Exception('listxattr failed')
        return [os.fsdecode(name) for name in namebuf.raw.split(b'\0')[:-1]]

    def getxattr(path, name, *, follow_symlinks=True):
        name = os.fsencode(name)
        func = libc.getxattr
        flags = 0
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.fgetxattr
        elif not follow_symlinks:
            flags = XATTR_NOFOLLOW
        n = _check(func(path, name, None, 0, 0, flags))
        if n == 0:
            return
        valuebuf = create_string_buffer(n)
        n2 = _check(func(path, name, valuebuf, n, 0, flags), path)
        if n2 != n:
            raise Exception('getxattr failed')
        return valuebuf.raw

    def setxattr(path, name, value, *, follow_symlinks=True):
        name = os.fsencode(name)
        value = value and os.fsencode(value)
        func = libc.setxattr
        flags = 0
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.fsetxattr
        elif not follow_symlinks:
            flags = XATTR_NOFOLLOW
        _check(func(path, name, value, len(value) if value else 0, 0, flags), path)

elif sys.platform.startswith('freebsd'):
    EXTATTR_NAMESPACE_USER = 0x0001
    libc.extattr_list_fd.argtypes = (c_int, c_int, c_char_p, c_size_t)
    libc.extattr_list_fd.restype = c_ssize_t
    libc.extattr_list_link.argtypes = (c_char_p, c_int, c_char_p, c_size_t)
    libc.extattr_list_link.restype = c_ssize_t
    libc.extattr_list_file.argtypes = (c_char_p, c_int, c_char_p, c_size_t)
    libc.extattr_list_file.restype = c_ssize_t
    libc.extattr_get_fd.argtypes = (c_int, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_get_fd.restype = c_ssize_t
    libc.extattr_get_link.argtypes = (c_char_p, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_get_link.restype = c_ssize_t
    libc.extattr_get_file.argtypes = (c_char_p, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_get_file.restype = c_ssize_t
    libc.extattr_set_fd.argtypes = (c_int, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_set_fd.restype = c_int
    libc.extattr_set_link.argtypes = (c_char_p, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_set_link.restype = c_int
    libc.extattr_set_file.argtypes = (c_char_p, c_int, c_char_p, c_char_p, c_size_t)
    libc.extattr_set_file.restype = c_int

    def listxattr(path, *, follow_symlinks=True):
        ns = EXTATTR_NAMESPACE_USER
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.extattr_list_fd
        elif follow_symlinks:
            func = libc.extattr_list_file
        else:
            func = libc.extattr_list_link
        n = _check(func(path, ns, None, 0), path)
        if n == 0:
            return []
        namebuf = create_string_buffer(n)
        n2 = _check(func(path, ns, namebuf, n), path)
        if n2 != n:
            raise Exception('listxattr failed')
        names = []
        mv = memoryview(namebuf.raw)
        while mv:
            length = mv[0]
            # Python < 3.3 returns bytes instead of int
            if isinstance(length, bytes):
                length = ord(length)
            names.append(os.fsdecode(bytes(mv[1:1+length])))
            mv = mv[1+length:]
        return names

    def getxattr(path, name, *, follow_symlinks=True):
        name = os.fsencode(name)
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.extattr_get_fd
        elif follow_symlinks:
            func = libc.extattr_get_file
        else:
            func = libc.extattr_get_link
        n = _check(func(path, EXTATTR_NAMESPACE_USER, name, None, 0))
        if n == 0:
            return
        valuebuf = create_string_buffer(n)
        n2 = _check(func(path, EXTATTR_NAMESPACE_USER, name, valuebuf, n), path)
        if n2 != n:
            raise Exception('getxattr failed')
        return valuebuf.raw

    def setxattr(path, name, value, *, follow_symlinks=True):
        name = os.fsencode(name)
        value = value and os.fsencode(value)
        if isinstance(path, str):
            path = os.fsencode(path)
        if isinstance(path, int):
            func = libc.extattr_set_fd
        elif follow_symlinks:
            func = libc.extattr_set_file
        else:
            func = libc.extattr_set_link
        _check(func(path, EXTATTR_NAMESPACE_USER, name, value, len(value) if value else 0), path)

else:
    def listxattr(path, *, follow_symlinks=True):
        return []

    def getxattr(path, name, *, follow_symlinks=True):
        pass

    def setxattr(path, name, value, *, follow_symlinks=True):
        pass
