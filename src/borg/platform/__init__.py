"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin

from .base import listxattr, getxattr, setxattr, ENOATTR
from .base import acl_get, acl_set
from .base import set_flags, get_flags
from .base import SaveFile, SyncFile, sync_dir, fdatasync, safe_fadvise
from .base import swidth, API_VERSION
from .base import process_alive, get_process_id, local_pid_alive, fqdn, hostname, hostid

OS_API_VERSION = API_VERSION

if not is_win32:
    from .posix import process_alive, local_pid_alive
    # POSIX swidth implementation works for: Linux, FreeBSD, Darwin, OpenIndiana, Cygwin
    from .posix import swidth
    from .posix import get_errno
    from .posix import uid2user, user2uid, gid2group, group2gid, getosusername

else:
    from .windows import process_alive, local_pid_alive
    from .windows import uid2user, user2uid, gid2group, group2gid, getosusername

if is_linux:  # pragma: linux only
    from .linux import API_VERSION as OS_API_VERSION
    from .linux import listxattr, getxattr, setxattr
    from .linux import acl_get, acl_set
    from .linux import set_flags, get_flags
    from .linux import SyncFile
elif is_freebsd:  # pragma: freebsd only
    from .freebsd import API_VERSION as OS_API_VERSION
    from .freebsd import listxattr, getxattr, setxattr
    from .freebsd import acl_get, acl_set
elif is_darwin:  # pragma: darwin only
    from .darwin import API_VERSION as OS_API_VERSION
    from .darwin import listxattr, getxattr, setxattr
    from .darwin import acl_get, acl_set
    from .darwin import is_darwin_feature_64_bit_inode, _get_birthtime_ns


def get_birthtime_ns(st, path, fd=None):
    if hasattr(st, "st_birthtime_ns"):
        # Added in Python 3.12 but not always available.
        return st.st_birthtime_ns
    elif is_darwin and is_darwin_feature_64_bit_inode:
        return _get_birthtime_ns(fd or path, follow_symlinks=False)
    elif hasattr(st, "st_birthtime"):
        return int(st.st_birthtime * 10**9)
    else:
        return None
