import sys

"""
Platform-specific APIs.

Public APIs are documented in platform.base.
"""

from .base import acl_get, acl_set
from .base import set_flags, get_flags
from .base import SaveFile, SyncFile, sync_dir, fdatasync
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
