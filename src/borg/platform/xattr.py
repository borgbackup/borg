import errno
import os

from ..helpers import Buffer


try:
    ENOATTR = errno.ENOATTR
except AttributeError:
    # on some platforms, ENOATTR is missing, use ENODATA there
    ENOATTR = errno.ENODATA


buffer = Buffer(bytearray, limit=2**24)


def split_string0(buf):
    """split a list of zero-terminated strings into python not-zero-terminated bytes"""
    if isinstance(buf, bytearray):
        buf = bytes(buf)  # use a bytes object, so we return a list of bytes objects
    return buf.split(b"\0")[:-1]


def split_lstring(buf):
    """split a list of length-prefixed strings into python not-length-prefixed bytes"""
    result = []
    mv = memoryview(buf)
    while mv:
        length = mv[0]
        result.append(bytes(mv[1 : 1 + length]))
        mv = mv[1 + length :]
    return result


class BufferTooSmallError(Exception):
    """the buffer given to a xattr function was too small for the result."""


def _check(rv, path=None, detect_buffer_too_small=False):
    from . import get_errno

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
                msg = ""
            if isinstance(path, int):
                path = "<FD %d>" % path
            raise OSError(e, msg, path)
    if detect_buffer_too_small and rv >= len(buffer):
        # freebsd does not error with ERANGE if the buffer is too small,
        # it just fills the buffer, truncates and returns.
        # so, we play safe and just assume that result is truncated if
        # it happens to be a full buffer.
        raise BufferTooSmallError
    return rv


def _listxattr_inner(func, path):
    assert isinstance(path, (bytes, int))
    size = len(buffer)
    while True:
        buf = buffer.get(size)
        try:
            n = _check(func(path, buf, size), path, detect_buffer_too_small=True)
        except BufferTooSmallError:
            size *= 2
        else:
            return n, buf


def _getxattr_inner(func, path, name):
    assert isinstance(path, (bytes, int))
    assert isinstance(name, bytes)
    size = len(buffer)
    while True:
        buf = buffer.get(size)
        try:
            n = _check(func(path, name, buf, size), path, detect_buffer_too_small=True)
        except BufferTooSmallError:
            size *= 2
        else:
            return n, buf


def _setxattr_inner(func, path, name, value):
    assert isinstance(path, (bytes, int))
    assert isinstance(name, bytes)
    assert isinstance(value, bytes)
    _check(func(path, name, value, len(value)), path, detect_buffer_too_small=False)
