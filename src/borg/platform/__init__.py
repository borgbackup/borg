import sys

"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from .base import acl_get, acl_set
from .base import set_flags, get_flags
from .base import SyncFile, sync_dir, fdatasync
from .base import swidth, API_VERSION

if sys.platform.startswith('linux'):  # pragma: linux only
    from .linux import acl_get, acl_set
    from .linux import set_flags, get_flags
    from .linux import SyncFile
    from .linux import swidth, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .freebsd import acl_get, acl_set
    from .freebsd import swidth, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .darwin import acl_get, acl_set
    from .darwin import swidth, API_VERSION
elif sys.platform == 'win32':  # pragma: windows only
    from .windows import acl_get, acl_set
    from .windows import API_VERSION
    from .windows import sync_dir
    from .windows import get_owner, set_owner
    from .windows import get_ads
    from .windows import select
