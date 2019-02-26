"""A basic extended attributes (xattr) implementation for Linux, FreeBSD and MacOS X."""

import errno
import os
import re
import subprocess
import sys
import tempfile

from distutils.version import LooseVersion

from .helpers import prepare_subprocess_env

from .logger import create_logger

logger = create_logger()

from .platform import listxattr, getxattr, setxattr, ENOATTR

# If we are running with fakeroot on Linux, then use the xattr functions of fakeroot. This is needed by
# the 'test_extract_capabilities' test, but also allows xattrs to work with fakeroot on Linux in normal use.
# TODO: Check whether fakeroot supports xattrs on all platforms supported below.
# TODO: If that's the case then we can make Borg fakeroot-xattr-compatible on these as well.
XATTR_FAKEROOT = False
if sys.platform.startswith('linux'):
    LD_PRELOAD = os.environ.get('LD_PRELOAD', '')
    preloads = re.split("[ :]", LD_PRELOAD)
    for preload in preloads:
        if preload.startswith("libfakeroot"):
            env = prepare_subprocess_env(system=True)
            fakeroot_output = subprocess.check_output(['fakeroot', '-v'], env=env)
            fakeroot_version = LooseVersion(fakeroot_output.decode('ascii').split()[-1])
            if fakeroot_version >= LooseVersion("1.20.2"):
                # 1.20.2 has been confirmed to have xattr support
                # 1.18.2 has been confirmed not to have xattr support
                # Versions in-between are unknown
                libc_name = preload
                XATTR_FAKEROOT = True
            break


def is_enabled(path=None):
    """Determine if xattr is enabled on the filesystem
    """
    with tempfile.NamedTemporaryFile(dir=path, prefix='borg-tmp') as f:
        fd = f.fileno()
        name, value = b'user.name', b'value'
        try:
            setxattr(fd, name, value)
        except OSError:
            return False
        try:
            names = listxattr(fd)
        except OSError:
            return False
        if name not in names:
            return False
        return getxattr(fd, name) == value


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
