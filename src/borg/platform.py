import sys

"""
Platform-specific APIs.

Public APIs are documented in platform_base.
"""

from .platform_base import acl_get, acl_set
from .platform_base import set_flags, get_flags
from .platform_base import SyncFile, sync_dir, fdatasync
from .platform_base import swidth, API_VERSION

if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set
    from .platform_linux import set_flags, get_flags
    from .platform_linux import SyncFile
    from .platform_linux import swidth, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set
    from .platform_freebsd import swidth, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set
    from .platform_darwin import swidth, API_VERSION
