import sys

"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from .base import acl_get, acl_set
from .base import set_flags, get_flags
from .base import SaveFile, SyncFile, sync_dir, fdatasync, safe_fadvise
from .base import swidth, umount, API_VERSION
from .base import process_alive, get_process_id, local_pid_alive

OS_API_VERSION = API_VERSION

if not sys.platform.startswith(('win32', )):
    from .posix import process_alive, get_process_id, local_pid_alive

if sys.platform.startswith('linux'):  # pragma: linux only
    from .linux import API_VERSION as OS_API_VERSION
    from .linux import acl_get, acl_set
    from .linux import set_flags, get_flags
    from .linux import SyncFile
    from .linux import swidth, umount
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .freebsd import API_VERSION as OS_API_VERSION
    from .freebsd import acl_get, acl_set
    from .freebsd import swidth, umount
elif sys.platform == 'darwin':  # pragma: darwin only
    from .darwin import API_VERSION as OS_API_VERSION
    from .darwin import acl_get, acl_set
    from .darwin import swidth, umount
