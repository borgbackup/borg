"""A basic extended attributes (xattr) implementation for Linux
"""
import os
import sys
from ctypes import CDLL, create_string_buffer, c_ssize_t, c_size_t, c_char_p, c_int, c_uint32, get_errno
from ctypes.util import find_library

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

    def set(path_or_fd, name, value):
        if isinstance(path_or_fd, int):
            fsetxattr(path_or_fd, b'user.' + name, value)
        else:
            lsetxattr(path_or_fd, b'user.' + name, value)

    def get_all(path_or_fd):
        """Return a dictionary with all (user) xattrs for "path_or_fd"

        Symbolic links are not followed
        """
        if isinstance(path_or_fd, int):
            return dict((name[5:], fgetxattr(path_or_fd, name)) for name in flistxattr(path_or_fd) if name.startswith(b'user.'))
        else:
            return dict((name[5:], lgetxattr(path_or_fd, name)) for name in llistxattr(path_or_fd) if name.startswith(b'user.'))

    def llistxattr(path):
        path = os.fsencode(path)
        n = _check(libc.llistxattr(path, None, 0), path)
        if n == 0:
            []
        namebuf = create_string_buffer(n)
        n2 = _check(libc.llistxattr(path, namebuf, n))
        if n2 != n:
            raise Exception('llistxattr failed')
        return namebuf.raw.split(b'\0')[:-1]

    def flistxattr(fd):
        n = _check(libc.flistxattr(fd, None, 0))
        if n == 0:
            []
        namebuf = create_string_buffer(n)
        n2 = _check(libc.flistxattr(fd, namebuf, n))
        if n2 != n:
            raise Exception('flistxattr failed')
        return namebuf.raw.split(b'\0')[:-1]

    def lsetxattr(path, name, value, flags=0):
        _check(libc.lsetxattr(os.fsencode(path), name, value, len(value), flags), path)

    def fsetxattr(fd, name, value, flags=0):
        _check(libc.fsetxattr(fd, name, value, len(value), flags))

    def lgetxattr(path, name):
        path = os.fsencode(path)
        n = _check(libc.lgetxattr(path, name, None, 0))
        if n == 0:
            return None
        valuebuf = create_string_buffer(n)
        n2 = _check(libc.lgetxattr(path, name, valuebuf, n), path)
        if n2 != n:
            raise Exception('lgetxattr failed')
        return valuebuf.raw

    def fgetxattr(fd, name):
        n = _check(libc.fgetxattr(fd, name, None, 0))
        if n == 0:
            return None
        valuebuf = create_string_buffer(n)
        n2 = _check(libc.fgetxattr(fd, name, valuebuf, n))
        if n2 != n:
            raise Exception('fgetxattr failed')
        return valuebuf.raw

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

    def set(path_or_fd, name, value):
        if isinstance(path_or_fd, int):
            fsetxattr(path_or_fd, name, value)
        else:
            lsetxattr(path_or_fd, name, value)

    def get_all(path_or_fd):
        """Return a dictionary with all (user) xattrs for "path_or_fd"

        Symbolic links are not followed
        """
        if isinstance(path_or_fd, int):
            return dict((name, fgetxattr(path_or_fd, name)) for name in flistxattr(path_or_fd))
        else:
            return dict((name, lgetxattr(path_or_fd, name)) for name in llistxattr(path_or_fd))

    def llistxattr(path):
        path = os.fsencode(path)
        n = _check(libc.listxattr(path, None, 0, XATTR_NOFOLLOW), path)
        if n == 0:
            []
        namebuf = create_string_buffer(n)
        n2 = _check(libc.listxattr(path, namebuf, n, XATTR_NOFOLLOW))
        if n2 != n:
            raise Exception('llistxattr failed')
        return namebuf.raw.split(b'\0')[:-1]

    def flistxattr(fd):
        n = _check(libc.flistxattr(fd, None, 0, 0))
        if n == 0:
            []
        namebuf = create_string_buffer(n)
        n2 = _check(libc.flistxattr(fd, namebuf, n, 0))
        if n2 != n:
            raise Exception('flistxattr failed')
        return namebuf.raw.split(b'\0')[:-1]

    def lsetxattr(path, name, value, flags=XATTR_NOFOLLOW):
        _check(libc.setxattr(os.fsencode(path), name, value, len(value), 0, flags), path)

    def fsetxattr(fd, name, value, flags=0):
        _check(libc.fsetxattr(fd, name, value, len(value), 0, flags))

    def lgetxattr(path, name):
        path = os.fsencode(path)
        n = _check(libc.getxattr(path, name, None, 0, 0, XATTR_NOFOLLOW), path)
        if n == 0:
            return None
        valuebuf = create_string_buffer(n)
        n2 = _check(libc.getxattr(path, name, valuebuf, n, 0, XATTR_NOFOLLOW))
        if n2 != n:
            raise Exception('getxattr failed')
        return valuebuf.raw

    def fgetxattr(fd, name):
        n = _check(libc.fgetxattr(fd, name, None, 0, 0, 0))
        if n == 0:
            return None
        valuebuf = create_string_buffer(n)
        n2 = _check(libc.fgetxattr(fd, name, valuebuf, n, 0, 0))
        if n2 != n:
            Exception('fgetxattr failed')
        return valuebuf.raw

else:
    raise Exception('Unsupported platform: %s' % sys.platform)
