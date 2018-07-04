"""A basic extended attributes (xattr) implementation for Linux, FreeBSD and MacOS X."""

import errno
import tempfile

from .platform import listxattr, getxattr, setxattr, ENOATTR

XATTR_FAKEROOT = True  # fakeroot with xattr support required (>= 1.20.2?)


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
    """
    Return all extended attributes on *path* as a mapping.

    *path* can either be a path (str or bytes) or an open file descriptor (int).
    *follow_symlinks* indicates whether symlinks should be followed
    and only applies when *path* is not an open file descriptor.

    The returned mapping maps xattr names (str) to values (bytes or None).
    None indicates, as a xattr value, an empty value, i.e. a value of length zero.
    """
    try:
        result = {}
        names = listxattr(path, follow_symlinks=follow_symlinks)
        for name in names:
            try:
                # if we get an empty xattr value (b''), we store None into the result dict.
                # borg always did it like that...
                result[name] = getxattr(path, name, follow_symlinks=follow_symlinks) or None
            except OSError as e:
                # if we get ENOATTR, a race has happened: xattr names were deleted after list.
                # we just ignore the now missing ones. if you want consistency, do snapshots.
                if e.errno != ENOATTR:
                    raise
        return result
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EPERM):
            return {}
