"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin

from .base import ENOATTR, API_VERSION
from .base import SaveFile, sync_dir, fdatasync, safe_fadvise
from .base import get_process_id, fqdn, hostname, hostid

if is_linux:  # pragma: linux only
    from .linux import API_VERSION as OS_API_VERSION
    from .linux import listxattr, getxattr, setxattr
    from .linux import acl_get, acl_set
    from .linux import set_flags, get_flags
    from .linux import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import swidth
    from .posix import get_errno
    from .posix import uid2user, user2uid, gid2group, group2gid, getosusername
elif is_freebsd:  # pragma: freebsd only
    from .freebsd import API_VERSION as OS_API_VERSION
    from .freebsd import listxattr, getxattr, setxattr
    from .freebsd import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import swidth
    from .posix import get_errno
    from .posix import uid2user, user2uid, gid2group, group2gid, getosusername
elif is_darwin:  # pragma: darwin only
    from .darwin import API_VERSION as OS_API_VERSION
    from .darwin import listxattr, getxattr, setxattr
    from .darwin import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import swidth
    from .posix import get_errno
    from .posix import uid2user, user2uid, gid2group, group2gid, getosusername
elif not is_win32:  # pragma: posix only
    # generic stuff for all other posix OSes
    OS_API_VERSION = API_VERSION
    from .base import listxattr, getxattr, setxattr
    from .base import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .posix import process_alive, local_pid_alive
    from .posix import swidth
    from .posix import get_errno
    from .posix import uid2user, user2uid, gid2group, group2gid, getosusername
else:  # pragma: win32 only
    # win32 specific stuff
    OS_API_VERSION = API_VERSION
    from .base import listxattr, getxattr, setxattr
    from .base import acl_get, acl_set
    from .base import set_flags, get_flags
    from .base import SyncFile
    from .windows import process_alive, local_pid_alive
    from .base import swidth
    from .windows import uid2user, user2uid, gid2group, group2gid, getosusername
