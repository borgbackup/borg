import errno
import os
import sys


# POSIX-only, from borg 1.1 platform.base
def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as os_error:
        # Some network filesystems don't support this and fail with EINVAL.
        # Other error codes (e.g. EIO) shouldn't be silenced.
        if os_error.errno != errno.EINVAL:
            raise
    finally:
        os.close(fd)


if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set, API_VERSION
else:  # pragma: unknown platform only
    API_VERSION = 2

    def acl_get(path, item, st, numeric_owner=False):
        pass

    def acl_set(path, item, numeric_owner=False):
        pass
