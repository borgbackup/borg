"""A basic extended attributes (xattr) implementation for Linux, FreeBSD and MacOS X."""

import errno
import os
import tempfile

from .logger import create_logger

logger = create_logger()

from .platform import listxattr, getxattr, setxattr, ENOATTR

XATTR_FAKEROOT = True  # fakeroot with xattr support required (>= 1.20.2?)


def is_enabled(path=None):
    """Determine if xattr is enabled on the filesystem
    """
    with tempfile.NamedTemporaryFile(dir=path, prefix='borg-tmp') as fd:
        try:
            setxattr(fd.fileno(), b'user.name', b'value')
        except OSError:
            return False
        return getxattr(fd.fileno(), b'user.name') == b'value'


def get_all(path, follow_symlinks=False):
    """
    Return all extended attributes on *path* as a mapping.

    *path* can either be a path (str or bytes) or an open file descriptor (int).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.

    The returned mapping maps xattr names (bytes) to values (bytes or None).
    None indicates, as a xattr value, an empty value, i.e. a value of length zero.
    """
    if isinstance(path, str):
        path = os.fsencode(path)
    result = {}
    try:
        names = listxattr(path, follow_symlinks=follow_symlinks)
        for name in names:
            try:
                # xattr name is a bytes object, we directly use it.
                # if we get an empty xattr value (b''), we store None into the result dict -
                # borg always did it like that...
                result[name] = getxattr(path, name, follow_symlinks=follow_symlinks) or None
            except OSError as e:
                name_str = name.decode()
                if isinstance(path, int):
                    path_str = '<FD %d>' % path
                else:
                    path_str = os.fsdecode(path)
                if e.errno == ENOATTR:
                    # if we get ENOATTR, a race has happened: xattr names were deleted after list.
                    # we just ignore the now missing ones. if you want consistency, do snapshots.
                    pass
                elif e.errno == errno.EPERM:
                    # we were not permitted to read this attribute, still can continue trying to read others
                    logger.warning('%s: Operation not permitted when reading extended attribute %s' % (
                                   path_str, name_str))
                else:
                    raise
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EPERM):
            # if xattrs are not supported on the filesystem, we give up.
            # EPERM might be raised by listxattr.
            pass
        else:
            raise
    return result


def set_all(path, xattrs, follow_symlinks=False):
    """
    Set all extended attributes on *path* from a mapping.

    *path* can either be a path (str or bytes) or an open file descriptor (int).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.
    *xattrs* is mapping maps xattr names (bytes) to values (bytes or None).
    None indicates, as a xattr value, an empty value, i.e. a value of length zero.

    Return warning status (True means a non-fatal exception has happened and was dealt with).
    """
    if isinstance(path, str):
        path = os.fsencode(path)
    warning = False
    for k, v in xattrs.items():
        try:
            # the key k is a bytes object due to msgpack unpacking it as such.
            # if we have a None value, it means "empty", so give b'' to setxattr in that case:
            setxattr(path, k, v or b'', follow_symlinks=follow_symlinks)
        except OSError as e:
            warning = True
            k_str = k.decode()
            if isinstance(path, int):
                path_str = '<FD %d>' % path
            else:
                path_str = os.fsdecode(path)
            if e.errno == errno.E2BIG:
                logger.warning('%s: Value or key of extended attribute %s is too big for this filesystem' % (
                               path_str, k_str))
            elif e.errno == errno.ENOTSUP:
                logger.warning('%s: Extended attributes are not supported on this filesystem' % path_str)
            elif e.errno == errno.EACCES:
                # permission denied to set this specific xattr (this may happen related to security.* keys)
                logger.warning('%s: Permission denied when setting extended attribute %s' % (path_str, k_str))
            elif e.errno == errno.ENOSPC:
                # ext4 reports ENOSPC when trying to set an xattr with >4kiB while ext4 can only support 4kiB xattrs
                # (in this case, this is NOT a "disk full" error, just a ext4 limitation).
                logger.warning('%s: No space left on device while setting extended attribute %s (len = %d)' % (
                               path_str, k_str, len(v)))
            else:
                raise
    return warning
