"""A basic extended attributes (xattr) implementation for Linux, FreeBSD and macOS."""

import errno
import os
import re
import subprocess
import sys
import tempfile

from packaging.version import parse as parse_version

from .helpers import prepare_subprocess_env

from .logger import create_logger

logger = create_logger()

from .platform import listxattr, getxattr, setxattr, ENOATTR

# If we are running with fakeroot on Linux, then use the xattr functions of fakeroot. This is needed by
# the 'test_extract_capabilities' test, but also allows xattrs to work with fakeroot on Linux in normal use.
# TODO: Check whether fakeroot supports xattrs on all platforms supported below.
# TODO: If that's the case then we can make Borg fakeroot-xattr-compatible on these as well.
XATTR_FAKEROOT = False
if sys.platform.startswith("linux"):
    LD_PRELOAD = os.environ.get("LD_PRELOAD", "")
    preloads = re.split("[ :]", LD_PRELOAD)
    for preload in preloads:
        if preload.startswith("libfakeroot"):
            env = prepare_subprocess_env(system=True)
            fakeroot_output = subprocess.check_output(["fakeroot", "-v"], env=env)  # nosec B603, B607
            fakeroot_version = parse_version(fakeroot_output.decode("ascii").split()[-1])
            if fakeroot_version >= parse_version("1.20.2"):
                # 1.20.2 has been confirmed to have xattr support
                # 1.18.2 has been confirmed not to have xattr support
                # Versions in-between are unknown
                XATTR_FAKEROOT = True
            break


def is_enabled(path=None):
    """Determine if xattr is enabled on the filesystem"""
    with tempfile.NamedTemporaryFile(dir=path, prefix="borg-tmp") as f:
        fd = f.fileno()
        name, value = b"user.name", b"value"
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
                result[name] = getxattr(path, name, follow_symlinks=follow_symlinks)
            except OSError as e:
                # note: platform.xattr._check has already made a nice exception e with errno, msg, path/fd
                if e.errno in (ENOATTR,):  # errors we just ignore silently
                    # ENOATTR: a race has happened: xattr names were deleted after list.
                    pass
                else:  # all others: warn, skip this single xattr name, continue processing other xattrs
                    # EPERM: we were not permitted to read this attribute
                    # EINVAL: maybe xattr name is invalid or other issue, #6988
                    logger.warning("when getting extended attribute %s: %s", name.decode(errors="replace"), str(e))
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
            setxattr(path, k, v, follow_symlinks=follow_symlinks)
        except OSError as e:
            # note: platform.xattr._check has already made a nice exception e with errno, msg, path/fd
            warning = True
            if e.errno == errno.E2BIG:
                err_str = "too big for this filesystem (%s)" % str(e)
            elif e.errno == errno.ENOSPC:
                # ext4 reports ENOSPC when trying to set an xattr with >4kiB while ext4 can only support 4kiB xattrs
                # (in this case, this is NOT a "disk full" error, just a ext4 limitation).
                err_str = "fs full or xattr too big? [xattr len = %d] (%s)" % (len(v), str(e))
            else:
                # generic handler
                # EACCES: permission denied to set this specific xattr (this may happen related to security.* keys)
                # EPERM: operation not permitted
                err_str = str(e)
            logger.warning("when setting extended attribute %s: %s", k.decode(errors="replace"), err_str)
    return warning
