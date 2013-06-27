"""A basic extended attributes (xattr) implementation for Linux
"""
import os
from ctypes import CDLL, create_string_buffer, c_size_t, c_char_p, c_int, get_errno
from ctypes.util import find_library

libc = CDLL(find_library('c'), use_errno=True)
libc.llistxattr.argtypes = (c_char_p, c_char_p, c_size_t)
libc.llistxattr.restype = c_size_t
libc.flistxattr.argtypes = (c_int, c_char_p, c_size_t)
libc.flistxattr.restype = c_size_t
libc.lsetxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t, c_int)
libc.lsetxattr.restype = c_int
libc.lgetxattr.argtypes = (c_char_p, c_char_p, c_char_p, c_size_t)
libc.lgetxattr.restype = c_size_t


def set(path_or_fd, name, value):
    if isinstance(path_or_fd, int):
        fsetxattr(path_or_fd, b'user.' + name, value)
    else:
        lsetxattr(path_or_fd, b'user.' + name, value)


def get_all(path_or_fd):
    """Return a dictionary with all (user) xattrs for "path_or_fd"
    """
    if isinstance(path_or_fd, int):
        return dict((name[5:], fgetxattr(path_or_fd, name)) for name in flistxattr(path_or_fd) if name.startswith(b'user.'))
    else:
        return dict((name[5:], lgetxattr(path_or_fd, name)) for name in llistxattr(path_or_fd) if name.startswith(b'user.'))


def llistxattr(path):
    path = os.fsencode(path)
    n = libc.llistxattr(path, None, 0)
    if n == 0:
        []
    elif n < 0:
        raise OSError(get_errno())
    namebuf = create_string_buffer(n)
    assert libc.llistxattr(path, namebuf, n) == n
    return namebuf.raw.split(b'\0')[:-1]


def flistxattr(fd):
    n = libc.flistxattr(fd, None, 0)
    if n == 0:
        []
    elif n < 0:
        raise OSError(get_errno())
    namebuf = create_string_buffer(n)
    assert libc.flistxattr(fd, namebuf, n) == n
    return namebuf.raw.split(b'\0')[:-1]


def lsetxattr(path, name, value, flags=0):
    rv = libc.lsetxattr(os.fsencode(path), name, value, len(value), flags)
    if rv:
        raise OSError(get_errno())


def fsetxattr(fd, name, value, flags=0):
    rv = libc.fsetxattr(fd, name, value, len(value), flags)
    if rv:
        raise OSError(get_errno())


def lgetxattr(path, name):
    path = os.fsencode(path)
    n = libc.lgetxattr(path, name, None, 0)
    if n == 0:
        return None
    elif n < 0:
        raise OSError(get_errno())
    valuebuf = create_string_buffer(n)
    assert libc.lgetxattr(path, name, valuebuf, n) == n
    return valuebuf.raw


def fgetxattr(fd, name):
    n = libc.fgetxattr(fd, name, None, 0)
    if n == 0:
        return None
    elif n < 0:
        raise OSError(get_errno())
    valuebuf = create_string_buffer(n)
    assert libc.fgetxattr(fd, name, valuebuf, n) == n
    return valuebuf.raw
