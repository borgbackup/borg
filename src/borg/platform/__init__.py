"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from types import ModuleType

from ..platformflags import is_win32, is_linux, is_freebsd, is_netbsd, is_darwin, is_cygwin, is_haiku

from .base import ENOATTR
from .base import SaveFile, sync_dir, fdatasync, safe_fadvise
from .base import get_process_id, fqdn, hostname, hostid, swidth

# work around pyinstaller "forgetting" to include the xattr module
from . import xattr  # noqa: F401

platform_ug: ModuleType | None = None  # make mypy happy

if is_linux:  # pragma: linux only
    from .linux import listxattr, getxattr, setxattr
    from .linux import acl_get, acl_set
    from .linux import set_flags, get_flags
    from .linux import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import get_errno
    from .posix import getosusername
    from . import posix_ug as platform_ug
elif is_freebsd:  # pragma: freebsd only
    from .freebsd import listxattr, getxattr, setxattr
    from .freebsd import acl_get, acl_set
    from .freebsd import set_flags
    from .base import get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import get_errno
    from .posix import getosusername
    from . import posix_ug as platform_ug
elif is_netbsd:  # pragma: netbsd only
    from .netbsd import listxattr, getxattr, setxattr
    from .base import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import get_errno
    from .posix import getosusername
    from . import posix_ug as platform_ug
elif is_darwin:  # pragma: darwin only
    from .darwin import listxattr, getxattr, setxattr
    from .darwin import acl_get, acl_set
    from .darwin import is_darwin_feature_64_bit_inode, _get_birthtime_ns
    from .darwin import set_flags
    from .darwin import fdatasync, sync_dir  # type: ignore[no-redef]
    from .base import get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import get_errno
    from .posix import getosusername
    from . import posix_ug as platform_ug
elif not is_win32:  # pragma: posix only
    # Generic code for all other POSIX OSes
    from .base import listxattr, getxattr, setxattr
    from .base import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import get_errno
    from .posix import getosusername
    from . import posix_ug as platform_ug
else:  # pragma: win32 only
    # Win32-specific stuff
    from .base import listxattr, getxattr, setxattr
    from .base import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .windows import process_alive, local_pid_alive
    from .windows import getosusername
    from . import windows_ug as platform_ug


def get_birthtime_ns(st, path, fd=None):
    if hasattr(st, "st_birthtime_ns"):
        # Added in Python 3.12, but not always available.
        return st.st_birthtime_ns
    elif is_darwin and is_darwin_feature_64_bit_inode:
        return _get_birthtime_ns(fd or path, follow_symlinks=False)
    elif hasattr(st, "st_birthtime"):
        return int(st.st_birthtime * 10**9)
    else:
        return None


# have some wrapper functions, so we can monkeypatch the functions in platform_ug.
# for normal usage from outside the platform package, always import these:
def uid2user(uid, default=None):
    return platform_ug._uid2user(uid, default)


def gid2group(gid, default=None):
    return platform_ug._gid2group(gid, default)


def user2uid(user, default=None):
    return platform_ug._user2uid(user, default)


def group2gid(group, default=None):
    return platform_ug._group2gid(group, default)
