"""A basic extended attributes (xattr) implementation for Linux, FreeBSD and MacOS X."""

import errno
import os
import re
import subprocess
import sys
import tempfile
from ctypes import CDLL, create_string_buffer, c_ssize_t, c_size_t, c_char_p, c_int, c_uint32, get_errno
from ctypes.util import find_library
from distutils.version import LooseVersion

from .helpers import Buffer

from .logger import create_logger
logger = create_logger()


try:
    ENOATTR = errno.ENOATTR
except AttributeError:
    # on some platforms, ENOATTR is missing, use ENODATA there
    ENOATTR = errno.ENODATA


buffer = Buffer(create_string_buffer, limit=2**24)


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
        result = {}
        names = listxattr(path, follow_symlinks=follow_symlinks)
        for name in names:
            try:
                result[name] = getxattr(path, name, follow_symlinks=follow_symlinks)
            except OSError as e:
                # if we get ENOATTR, a race has happened: xattr names were deleted after list.
                # we just ignore the now missing ones. if you want consistency, do snapshots.
                if e.errno != ENOATTR:
                    raise
        return result
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EPERM):
            return {}


libc_name = find_library('c')
if libc_name is None:
    # find_library didn't work, maybe we are on some minimal system that misses essential
    # tools used by find_library, like ldconfig, gcc/cc, objdump.
    # so we can only try some "usual" names for the C library:
    if sys.platform.startswith('linux'):
        libc_name = 'libc.so.6'
    elif sys.platform.startswith(('freebsd', 'netbsd')):
        libc_name = 'libc.so'
    elif sys.platform == 'darwin':
        libc_name = 'libc.dylib'
    else:
        msg = "Can't find C library. No fallback known. Try installing ldconfig, gcc/cc or objdump."
        logger.error(msg)
        raise Exception(msg)

# If we are running with fakeroot on Linux, then use the xattr functions of fakeroot. This is needed by
# the 'test_extract_capabilities' test, but also allows xattrs to work with fakeroot on Linux in normal use.
# TODO: Check whether fakeroot supports xattrs on all platforms supported below.
# TODO: If that's the case then we can make Borg fakeroot-xattr-compatible on these as well.
try:
    XATTR_FAKEROOT = False
    if sys.platform.startswith('linux'):
        LD_PRELOAD = os.environ.get('LD_PRELOAD', '')
        preloads = re.split("[ :]", LD_PRELOAD)
        for preload in preloads:
            if preload.startswith("libfakeroot"):
                fakeroot_version = LooseVersion(subprocess.check_output(['fakeroot', '-v']).decode('ascii').split()[-1])
                if fakeroot_version >= LooseVersion("1.20.2"):
                    # 1.20.2 has been confirmed to have xattr support
                    # 1.18.2 has been confirmed not to have xattr support
                    # Versions in-between are unknown
                    libc_name = preload
                    XATTR_FAKEROOT = True
                break
except:
    pass

try:
    libc = CDLL(libc_name, use_errno=True)
except OSError as e:
    msg = "Can't find C library [%s]. Try installing ldconfig, gcc/cc or objdump." % e
    raise Exception(msg)


def split_string0(buf):
    """split a list of zero-terminated strings into python not-zero-terminated bytes"""
    return buf.split(b'\0')[:-1]


def split_lstring(buf):
    """split a list of length-prefixed strings into python not-length-prefixed bytes"""
    result = []
    mv = memoryview(buf)
    while mv:
        length = mv[0]
        result.append(bytes(mv[1:1 + length]))
        mv = mv[1 + length:]
    return result


class BufferTooSmallError(Exception):
    """the buffer given to an xattr function was too small for the result"""


def _check(rv, path=None, detect_buffer_too_small=False):
    if rv < 0:
        e = get_errno()
        if detect_buffer_too_small and e == errno.ERANGE:
            # listxattr and getxattr signal with ERANGE that they need a bigger result buffer.
            # setxattr signals this way that e.g. a xattr key name is too long / inacceptable.
            raise BufferTooSmallError
        else:
            try:
                msg = os.strerror(e)
            except ValueError:
                msg = ''
            if isinstance(path, int):
                path = '<FD %d>' % path
            raise OSError(e, msg, path)
    if detect_buffer_too_small and rv >= len(buffer):
        # freebsd does not error with ERANGE if the buffer is too small,
        # it just fills the buffer, truncates and returns.
        # so, we play sure and just assume that result is truncated if
        # it happens to be a full buffer.
        raise BufferTooSmallError
    return rv


def _listxattr_inner(func, path):
    if isinstance(path, str):
        path = os.fsencode(path)
    size = len(buffer)
    while True:
        buf = buffer.get(size)
        try:
            n = _check(func(path, buf, size), path, detect_buffer_too_small=True)
        except BufferTooSmallError:
            size *= 2
        else:
            return n, buf.raw


def _getxattr_inner(func, path, name):
    if isinstance(path, str):
        path = os.fsencode(path)
    name = os.fsencode(name)
    size = len(buffer)
    while True:
        buf = buffer.get(size)
        try:
            n = _check(func(path, name, buf, size), path, detect_buffer_too_small=True)
        except BufferTooSmallError:
            size *= 2
        else:
            return n, buf.raw


def _setxattr_inner(func, path, name, value):
    if isinstance(path, str):
        path = os.fsencode(path)
    name = os.fsencode(name)
    value = value and os.fsencode(value)
    size = len(value) if value else 0
    _check(func(path, name, value, size), path, detect_buffer_too_small=False)


if sys.platform.startswith('linux'):  # pragma: linux only
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
        def func(path, buf, size):
            if isinstance(path, int):
                return libc.flistxattr(path, buf, size)
            else:
                if follow_symlinks:
                    return libc.listxattr(path, buf, size)
                else:
                    return libc.llistxattr(path, buf, size)

        n, buf = _listxattr_inner(func, path)
        return [os.fsdecode(name) for name in split_string0(buf[:n])
                if not name.startswith(b'system.posix_acl_')]

    def getxattr(path, name, *, follow_symlinks=True):
        def func(path, name, buf, size):
            if isinstance(path, int):
                return libc.fgetxattr(path, name, buf, size)
            else:
                if follow_symlinks:
                    return libc.getxattr(path, name, buf, size)
                else:
                    return libc.lgetxattr(path, name, buf, size)

        n, buf = _getxattr_inner(func, path, name)
        return buf[:n] or None

    def setxattr(path, name, value, *, follow_symlinks=True):
        def func(path, name, value, size):
            flags = 0
            if isinstance(path, int):
                return libc.fsetxattr(path, name, value, size, flags)
            else:
                if follow_symlinks:
                    return libc.setxattr(path, name, value, size, flags)
                else:
                    return libc.lsetxattr(path, name, value, size, flags)

        _setxattr_inner(func, path, name, value)

elif sys.platform == 'darwin':  # pragma: darwin only
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

    XATTR_NOFLAGS = 0x0000
    XATTR_NOFOLLOW = 0x0001

    def listxattr(path, *, follow_symlinks=True):
        def func(path, buf, size):
            if isinstance(path, int):
                return libc.flistxattr(path, buf, size, XATTR_NOFLAGS)
            else:
                if follow_symlinks:
                    return libc.listxattr(path, buf, size, XATTR_NOFLAGS)
                else:
                    return libc.listxattr(path, buf, size, XATTR_NOFOLLOW)

        n, buf = _listxattr_inner(func, path)
        return [os.fsdecode(name) for name in split_string0(buf[:n])]

    def getxattr(path, name, *, follow_symlinks=True):
        def func(path, name, buf, size):
            if isinstance(path, int):
                return libc.fgetxattr(path, name, buf, size, 0, XATTR_NOFLAGS)
            else:
                if follow_symlinks:
                    return libc.getxattr(path, name, buf, size, 0, XATTR_NOFLAGS)
                else:
                    return libc.getxattr(path, name, buf, size, 0, XATTR_NOFOLLOW)

        n, buf = _getxattr_inner(func, path, name)
        return buf[:n] or None

    def setxattr(path, name, value, *, follow_symlinks=True):
        def func(path, name, value, size):
            if isinstance(path, int):
                return libc.fsetxattr(path, name, value, size, 0, XATTR_NOFLAGS)
            else:
                if follow_symlinks:
                    return libc.setxattr(path, name, value, size, 0, XATTR_NOFLAGS)
                else:
                    return libc.setxattr(path, name, value, size, 0, XATTR_NOFOLLOW)

        _setxattr_inner(func, path, name, value)

elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
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
    ns = EXTATTR_NAMESPACE_USER = 0x0001

    def listxattr(path, *, follow_symlinks=True):
        def func(path, buf, size):
            if isinstance(path, int):
                return libc.extattr_list_fd(path, ns, buf, size)
            else:
                if follow_symlinks:
                    return libc.extattr_list_file(path, ns, buf, size)
                else:
                    return libc.extattr_list_link(path, ns, buf, size)

        n, buf = _listxattr_inner(func, path)
        return [os.fsdecode(name) for name in split_lstring(buf[:n])]

    def getxattr(path, name, *, follow_symlinks=True):
        def func(path, name, buf, size):
            if isinstance(path, int):
                return libc.extattr_get_fd(path, ns, name, buf, size)
            else:
                if follow_symlinks:
                    return libc.extattr_get_file(path, ns, name, buf, size)
                else:
                    return libc.extattr_get_link(path, ns, name, buf, size)

        n, buf = _getxattr_inner(func, path, name)
        return buf[:n] or None

    def setxattr(path, name, value, *, follow_symlinks=True):
        def func(path, name, value, size):
            if isinstance(path, int):
                return libc.extattr_set_fd(path, ns, name, value, size)
            else:
                if follow_symlinks:
                    return libc.extattr_set_file(path, ns, name, value, size)
                else:
                    return libc.extattr_set_link(path, ns, name, value, size)

        _setxattr_inner(func, path, name, value)

else:  # pragma: unknown platform only
    def listxattr(path, *, follow_symlinks=True):
        return []

    def getxattr(path, name, *, follow_symlinks=True):
        pass

    def setxattr(path, name, value, *, follow_symlinks=True):
        pass
